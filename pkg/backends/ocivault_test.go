package backends_test

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/argoproj-labs/argocd-vault-plugin/pkg/backends"
	ocism "github.com/oracle/oci-go-sdk/v65/secrets"
)

type mockOCIVaultClient struct {
	backends.OCIVaultIface
}

func (m *mockOCIVaultClient) GetSecretBundleByName(ctx context.Context, request ocism.GetSecretBundleByNameRequest) (response ocism.GetSecretBundleByNameResponse, err error) {
	data := ocism.GetSecretBundleByNameResponse{}

	switch *request.VaultId {
	case "test":
		if *request.VersionNumber == 0 {
			content := "current-value"
			secretBundle := ocism.Base64SecretBundleContentDetails{
				Content: &content,
			}
			data.SecretBundle.SecretBundleContent = secretBundle
		} else  {
			content := "previous-value"
			secretBundle := ocism.Base64SecretBundleContentDetails{
				Content: &content,
			}
			data.SecretBundle.SecretBundleContent = secretBundle
		} 

	}

	return data, nil
}

func TestOCIVaultGetSecrets(t *testing.T) {
	sm := backends.NewOCIVaultBackend(&mockOCIVaultClient{})

	t.Run("Get secrets", func(t *testing.T) {
		data, err := sm.GetSecrets("vault/test/secrets/secretname", "", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := map[string]interface{}{
			"secretname": "current-value",
		}

		if !reflect.DeepEqual(expected, data) {
			t.Errorf("expected: %s, got: %s.", expected, data)
		}
	})

	t.Run("OCI GetIndividualSecret", func(t *testing.T) {
		secret, err := sm.GetIndividualSecret("vault/test/secrets/secretname", "secretname", "2", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := "previous-value"

		if !reflect.DeepEqual(expected, secret) {
			t.Errorf("expected: %s, got: %s.", expected, secret)
		}
	})

	t.Run("OCI Get Secrets At Specific Version", func(t *testing.T) {
		data, err := sm.GetSecrets("vault/test/secrets/secretname", "2", map[string]string{})
		if err != nil {
			t.Fatalf("expected 0 errors but got: %s", err)
		}

		expected := map[string]interface{}{
			"secretname": "previous-value",
		}

		if !reflect.DeepEqual(expected, data) {
			t.Errorf("expected: %s, got: %s.", expected, data)
		}
	})

	t.Run("OCI Invalid Path", func(t *testing.T) {
		_, err := sm.GetSecrets("ibmcloud/arbitrary/secrets/groups/some-group", "", map[string]string{})
		if err == nil {
			t.Fatalf("expected error")
		}

		expectedErr := "path is not in the correct format"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("Expected error to have %s but said %s", expectedErr, err)
		}
	})

	t.Run("OCI Invalid Version Number", func(t *testing.T) {
		_, err := sm.GetSecrets("vault/test/secrets/secretname", "eleven", map[string]string{})
		if err == nil {
			t.Fatalf("expected error")
		}

		expectedErr := "version string must contain only positive integers"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("Expected error to have %s but said %s", expectedErr, err)
		}
	})

	t.Run("OCI Negative Version Number", func(t *testing.T) {
		_, err := sm.GetSecrets("vault/test/secrets/secretname", "-1", map[string]string{})
		if err == nil {
			t.Fatalf("expected error")
		}

		expectedErr := "version string must contain only positive integers"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("Expected error to have %s but said %s", expectedErr, err)
		}
	})

	t.Run("OCI Float Version Number", func(t *testing.T) {
		_, err := sm.GetSecrets("vault/test/secrets/secretname", "1.0", map[string]string{})
		if err == nil {
			t.Fatalf("expected error")
		}

		expectedErr := "version string must contain only positive integers"
		if !strings.Contains(err.Error(), expectedErr) {
			t.Fatalf("Expected error to have %s but said %s", expectedErr, err)
		}
	})

}
