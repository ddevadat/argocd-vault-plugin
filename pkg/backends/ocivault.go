package backends

import (
	"context"
	"fmt"
	"regexp"
	"strconv"

	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/example/helpers"
	ocism "github.com/oracle/oci-go-sdk/v65/secrets"
)

// const (
// 	AWS_CURRENT  string = "AWSCURRENT"
// 	AWS_PREVIOUS string = "AWSPREVIOUS"
// )

var OCIPath, _ = regexp.Compile(`vault/(?P<vaultid>.+)/secrets/(?P<secretname>.+)`)

type OCIVaultIface interface {
	GetSecretBundleByName(ctx context.Context, request ocism.GetSecretBundleByNameRequest) (response ocism.GetSecretBundleByNameResponse, err error)
}

// OCIVault is a struct for working with a OCI Vault backend
type OCIVault struct {
	Client OCIVaultIface
}

// NewOCIVaultBackend initializes a new OCI Vault backend
func NewOCIVaultBackend(client OCIVaultIface) *OCIVault {
	return &OCIVault{
		Client: client,
	}
}

// Login does nothing as a "login" is handled on the instantiation of the aws sdk
func (oci *OCIVault) Login() error {
	return nil
}

// GetSecrets gets secrets from OCI Vault and returns the formatted data
// For OCI  Vault, the path is of format `vault/vaultid/secrets/secretname`
func (oci *OCIVault) GetSecrets(kvpath string, version string, annotations map[string]string) (map[string]interface{}, error) {

	matches := OCIPath.FindStringSubmatch(kvpath)
	if len(matches) == 0 {
		return nil, fmt.Errorf("path is not in the correct format (vault/<vaultid>/secrets/<secretname>) for OCI vault: %s", kvpath)
	}
	vaultId := matches[OCIPath.SubexpIndex("vaultid")]
	secretName := matches[OCIPath.SubexpIndex("secretname")]

	req := ocism.GetSecretBundleByNameRequest{
		VaultId:    common.String(vaultId),
		SecretName: common.String(secretName)}

	if version != "" {
		isPositiveInteger, _ := regexp.MatchString(`^\d+$`, version)
		if !isPositiveInteger {
			return nil, fmt.Errorf("version string must contain only positive integers")
		}
		secret_version, err := strconv.ParseInt(version, 10, 64)
		helpers.FatalIfError(err)
		req.VersionNumber = common.Int64(secret_version)
	} else {
		req.Stage = ocism.GetSecretBundleByNameStageLatest
	}

	resp, err := oci.Client.GetSecretBundleByName(context.Background(), req)
	helpers.FatalIfError(err)

	data := make(map[string]interface{})

	secretContent := resp.SecretBundle.SecretBundleContent.(ocism.Base64SecretBundleContentDetails)
	encodedSecret := *secretContent.Content

	data[secretName] = string(encodedSecret)
	return data, nil
}

// GetIndividualSecret will get the specific secret (placeholder) from the SM backend
// For OCI Vault, the path is of format `vault/vaultid/secrets/secretname`
// So, we use GetSecrets and extract the specific placeholder we want
func (oci *OCIVault) GetIndividualSecret(kvpath, secret, version string, annotations map[string]string) (interface{}, error) {
	data, err := oci.GetSecrets(kvpath, version, annotations)
	if err != nil {
		return nil, err
	}
	return data[secret], nil
}
