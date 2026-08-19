package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
)

const secureEnvelopeVersion = 1

type EphemeralKey struct {
	private *ecdh.PrivateKey
	public  []byte
}

func GenerateEphemeralKey() (*EphemeralKey, error) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &EphemeralKey{private: private, public: private.PublicKey().Bytes()}, nil
}

func (k *EphemeralKey) PublicKey() []byte {
	return append([]byte(nil), k.public...)
}

type SecureEnvelope struct {
	Version    int    `json:"version"`
	Sequence   uint64 `json:"sequence"`
	Ciphertext []byte `json:"ciphertext"`
}

type SecureSession struct {
	send       cipher.AEAD
	receive    cipher.AEAD
	sendPrefix [4]byte
	recvPrefix [4]byte
	sendMu     sync.Mutex
	recvMu     sync.Mutex
	sendSeq    uint64
	recvSeq    uint64
}

func DeriveSecureSession(local *EphemeralKey, remotePublic []byte, controller bool) (*SecureSession, error) {
	if local == nil || len(remotePublic) != 32 {
		return nil, errors.New("invalid secure channel key")
	}
	remote, err := ecdh.X25519().NewPublicKey(remotePublic)
	if err != nil {
		return nil, fmt.Errorf("parse secure channel key: %w", err)
	}
	shared, err := local.private.ECDH(remote)
	if err != nil {
		return nil, fmt.Errorf("derive secure channel secret: %w", err)
	}
	agentPublic, controllerPublic := local.public, remotePublic
	if controller {
		agentPublic, controllerPublic = remotePublic, local.public
	}
	salt := make([]byte, 0, len(agentPublic)+len(controllerPublic))
	salt = append(salt, agentPublic...)
	salt = append(salt, controllerPublic...)
	material := make([]byte, 72)
	if _, err := io.ReadFull(hkdf.New(sha256.New, shared, salt, []byte("mmwx-guard-secure-channel-v1")), material); err != nil {
		return nil, err
	}
	agentToControllerKey := material[:32]
	controllerToAgentKey := material[32:64]
	agentToControllerPrefix := material[64:68]
	controllerToAgentPrefix := material[68:72]
	var sendKey, receiveKey, sendPrefix, receivePrefix []byte
	if controller {
		sendKey, receiveKey = controllerToAgentKey, agentToControllerKey
		sendPrefix, receivePrefix = controllerToAgentPrefix, agentToControllerPrefix
	} else {
		sendKey, receiveKey = agentToControllerKey, controllerToAgentKey
		sendPrefix, receivePrefix = agentToControllerPrefix, controllerToAgentPrefix
	}
	send, err := newGCM(sendKey)
	if err != nil {
		return nil, err
	}
	receive, err := newGCM(receiveKey)
	if err != nil {
		return nil, err
	}
	session := &SecureSession{send: send, receive: receive}
	copy(session.sendPrefix[:], sendPrefix)
	copy(session.recvPrefix[:], receivePrefix)
	return session, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (s *SecureSession) EncryptMessage(message Message) (SecureEnvelope, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendSeq == ^uint64(0) {
		return SecureEnvelope{}, errors.New("secure channel sequence exhausted")
	}
	plain, err := json.Marshal(message)
	if err != nil {
		return SecureEnvelope{}, err
	}
	s.sendSeq++
	nonce := secureNonce(s.sendPrefix, s.sendSeq)
	aad := secureAAD(s.sendSeq)
	ciphertext := s.send.Seal(nil, nonce[:], plain, aad[:])
	return SecureEnvelope{Version: secureEnvelopeVersion, Sequence: s.sendSeq, Ciphertext: ciphertext}, nil
}

func (s *SecureSession) DecryptMessage(envelope SecureEnvelope) (Message, error) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if envelope.Version != secureEnvelopeVersion || envelope.Sequence != s.recvSeq+1 || len(envelope.Ciphertext) < s.receive.Overhead() {
		return Message{}, errors.New("invalid or replayed secure envelope")
	}
	nonce := secureNonce(s.recvPrefix, envelope.Sequence)
	aad := secureAAD(envelope.Sequence)
	plain, err := s.receive.Open(nil, nonce[:], envelope.Ciphertext, aad[:])
	if err != nil {
		return Message{}, errors.New("secure envelope authentication failed")
	}
	var message Message
	if err := json.Unmarshal(plain, &message); err != nil {
		return Message{}, errors.New("secure envelope payload is invalid")
	}
	s.recvSeq = envelope.Sequence
	return message, nil
}

func secureNonce(prefix [4]byte, sequence uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[:4], prefix[:])
	binary.BigEndian.PutUint64(nonce[4:], sequence)
	return nonce
}

func secureAAD(sequence uint64) [32]byte {
	context := []byte("mmwx-guard-secure-envelope-v1")
	input := make([]byte, len(context)+8)
	copy(input, context)
	binary.BigEndian.PutUint64(input[len(context):], sequence)
	return sha256.Sum256(input)
}

func HandshakeTranscript(agentID, machineID, challenge string, agentPublic, controllerPublic []byte) []byte {
	parts := [][]byte{[]byte("mmwx-guard-controller-proof-v1"), []byte(agentID), []byte(machineID), []byte(challenge), agentPublic, controllerPublic}
	total := 0
	for _, part := range parts {
		total += 4 + len(part)
	}
	out := make([]byte, 0, total)
	for _, part := range parts {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(part)))
		out = append(out, size[:]...)
		out = append(out, part...)
	}
	return out
}

func EncodeKey(value []byte) string { return base64.RawStdEncoding.EncodeToString(value) }

func DecodeKey(value string, size int) ([]byte, error) {
	decoded, err := base64.RawStdEncoding.DecodeString(value)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid encoded key")
	}
	return decoded, nil
}

func KeyFingerprint(publicKey []byte) string {
	digest := sha256.Sum256(publicKey)
	return hex.EncodeToString(digest[:])
}
