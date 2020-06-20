package linebot

import (
	cloudkms "cloud.google.com/go/kms/apiv1"
	"context"
	"encoding/json"
	"fmt"
	kmspb "google.golang.org/genproto/googleapis/cloud/kms/v1"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/line/line-bot-sdk-go/linebot"
)

var (
	secrets Secrets
)

type Secrets struct {
	LineChannelSecret      string `json:"line_channel_secret"`
	LineChannelAccessToken string `json:"line_channel_access_token"`
}

//func init() {
//	secretsJson, err :=
//}

func lineSecretsKmsKeyName() string {

}

func decryptLineSecrets() ([]byte, error) {
	enc, err := ioutil.ReadFile("secrets.json.enc")
	if err != nil {
		return nil, err
	}
	return decryptSymmetric(lineSecretsKmsKeyName(), enc)
}

func decryptSymmetric(keyName string, ciphertext []byte) ([]byte, error) {
	ctx := context.Background()
	client, err := cloudkms.NewKeyManagementClient(ctx)
	if err != nil {
		return nil, err
	}

	req := &kmspb.DecryptRequest{
		Name:       keyName,
		Ciphertext: ciphertext,
	}

	resp, err := client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}
