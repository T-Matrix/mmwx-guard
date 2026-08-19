package protocol

import "testing"

func TestSecureSessionRoundTripAndReplayRejection(t *testing.T) {
	agentKey, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	controllerKey, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	agentSession, err := DeriveSecureSession(agentKey, controllerKey.PublicKey(), false)
	if err != nil {
		t.Fatal(err)
	}
	controllerSession, err := DeriveSecureSession(controllerKey, agentKey.PublicKey(), true)
	if err != nil {
		t.Fatal(err)
	}
	message, _ := NewMessage(TypeTelemetry, "", map[string]bool{"ok": true})
	envelope, err := agentSession.EncryptMessage(message)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := controllerSession.DecryptMessage(envelope)
	if err != nil || decoded.Type != TypeTelemetry {
		t.Fatalf("decoded message = %#v, %v", decoded, err)
	}
	if _, err := controllerSession.DecryptMessage(envelope); err == nil {
		t.Fatal("replayed secure envelope accepted")
	}
	reply, _ := NewMessage(TypePing, "0123456789abcdef", map[string]bool{"ok": true})
	replyEnvelope, err := controllerSession.EncryptMessage(reply)
	if err != nil {
		t.Fatal(err)
	}
	if decodedReply, err := agentSession.DecryptMessage(replyEnvelope); err != nil || decodedReply.Type != TypePing {
		t.Fatalf("reverse message = %#v, %v", decodedReply, err)
	}
}

func TestSecureSessionRejectsTamperingAndOutOfOrderMessages(t *testing.T) {
	agentKey, _ := GenerateEphemeralKey()
	controllerKey, _ := GenerateEphemeralKey()
	agentSession, _ := DeriveSecureSession(agentKey, controllerKey.PublicKey(), false)
	controllerSession, _ := DeriveSecureSession(controllerKey, agentKey.PublicKey(), true)
	message, _ := NewMessage(TypeTelemetry, "", map[string]bool{"ok": true})
	first, _ := agentSession.EncryptMessage(message)
	second, _ := agentSession.EncryptMessage(message)
	if _, err := controllerSession.DecryptMessage(second); err == nil {
		t.Fatal("out-of-order secure envelope accepted")
	}
	first.Ciphertext[len(first.Ciphertext)-1] ^= 0xff
	if _, err := controllerSession.DecryptMessage(first); err == nil {
		t.Fatal("tampered secure envelope accepted")
	}
}
