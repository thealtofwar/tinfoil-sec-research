package tinfoil

import (
	"context"
	"testing"
	"time"

	"github.com/openai/openai-go/v3/option"
	"github.com/stretchr/testify/require"
	ehbpidentity "github.com/tinfoilsh/encrypted-http-body-protocol/identity"
	"github.com/tinfoilsh/tinfoil-go/enclave"
)

// Same as the 300 case but with openai-go default retry options (as a normal user would).
func TestVerify3_DefaultOpenAIOptions300(t *testing.T) {
	id, err := ehbpidentity.NewIdentity()
	require.NoError(t, err)
	log := &v3Log{}
	srv := v3Attacker(t, 300, "", "application/json", v3Forged, nil, log)
	defer srv.Close()
	v3Route(t, srv)
	h, err := enclave.PoCHandleWithVerification("router.example.com", "tinfoilsh/confidential-model-router", v3Verified(id.MarshalPublicKeyHex()))
	require.NoError(t, err)
	c, err := createClientFromHandle(h, defaultTransportMode, "", "secret", option.WithAPIKey("sk"))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := c.Chat.Completions.New(ctx, v3Params())
	require.NoError(t, err)
	t.Logf("RESULT default-opts 300: transport=%s content=%q requests=%d", c.Transport(), resp.Choices[0].Message.Content, len(log.get()))
}
