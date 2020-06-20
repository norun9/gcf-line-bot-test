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

func init() {
	secretsJson, err := decryptLineSecrets()
	if err != nil {
		log.Fatal("failed decrypt secrets", err)
		return
	}
	if err := json.Unmarshal(secretsJson, &secrets); err != nil {
		log.Fatal("failed json unmarshal secrets", err)
		return
	}
}

func Webhook(w http.ResponseWriter, r *http.Request) {
	client, err := linebot.New(secrets.LineChannelSecret, secrets.LineChannelAccessToken)
	if err != nil {
		http.Error(w, "Error init client", http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	events, err := client.ParseRequest(r)
	if err != nil {
		http.Error(w, "Error parse request", http.StatusBadRequest)
		log.Fatal(err)
		return
	}
	for _, event := range events {
		switch event.Type {
		case linebot.EventTypeMessage:
			message := linebot.NewTextMessage("Test")
			_, err := client.ReplyMessage(event.ReplyToken, message).Do()
			
		}
	}
}

func lineSecretsKmsKeyName() string {
	prjID := os.Getenv("GCP_PROJECT_ID")
	keyRingName :=os.Getenv("KMS_KEY_RING_NAME")
	keyName := os.Getenv("KMS_LINE_SECRETS_KEY_NAME")
	return fmt.Sprintf("projects/%s/locations/global/keyRings/%s/cryptoKeys/%s", prjID, keyRingName, keyName)
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
