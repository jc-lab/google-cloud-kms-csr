package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/cloudkms/v1"
)

var (
	oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}
)
var algoFlag *string

func main() {
	keyFlag := flag.String("key", "", "")
	commonNameFlag := flag.String("common-name", "", "")
	orgFlag := flag.String("org", "", "")
	emailFlag := flag.String("email", "", "")
	outFlag := flag.String("out", "out.csr", "")
	algoFlag = flag.String("algo", "", "")
	flag.Parse()

	oauthClient, err := google.DefaultClient(context.Background(), cloudkms.CloudPlatformScope)
	if err != nil {
		log.Fatal(err)
	}

	kmsService, err := cloudkms.New(oauthClient)
	if err != nil {
		log.Fatal(err)
	}

	s, err := NewGoogleKMSSigner(kmsService, *keyFlag)
	if err != nil {
		log.Fatal(err)
	}

	subj := pkix.Name{
		CommonName:         *commonNameFlag,
		Organization:       []string{*orgFlag},
		OrganizationalUnit: []string{""},
		Country:            []string{"US"},
		Province:           []string{"California"},
		Locality:           []string{"San Francisco"},
	}

	rawSubj := subj.ToRDNSequence()
	template := &x509.CertificateRequest{}

	if *emailFlag != "" {
		rawSubj = append(rawSubj, []pkix.AttributeTypeAndValue{
			{Type: oidEmailAddress, Value: *emailFlag},
		})

		template.EmailAddresses = []string{*emailFlag}
	}

	asn1Subj, err := asn1.Marshal(rawSubj)
	if err != nil {
		log.Fatal(err)
	}

	template.RawSubject = asn1Subj

	// TODO Make this a flag or read from s.PublicKey?
	//      https://cloud.google.com/kms/docs/algorithms
	//      https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys#CryptoKeyVersionTemplate
	switch *algoFlag {
	    case "SHA256WithRSA":
	        template.SignatureAlgorithm = x509.SHA256WithRSA
	    case "SHA384WithRSA":
	        template.SignatureAlgorithm = x509.SHA384WithRSA
	    case "SHA512WithRSA":
	        template.SignatureAlgorithm = x509.SHA512WithRSA
	    case "DSAWithSHA1":
	        template.SignatureAlgorithm = x509.DSAWithSHA1
	    case "DSAWithSHA256":
	        template.SignatureAlgorithm = x509.DSAWithSHA256
	    case "ECDSAWithSHA1":
	        template.SignatureAlgorithm = x509.ECDSAWithSHA1
	    case "ECDSAWithSHA256":
	        template.SignatureAlgorithm = x509.ECDSAWithSHA256
	    case "ECDSAWithSHA384":
	        template.SignatureAlgorithm = x509.ECDSAWithSHA384
	    case "ECDSAWithSHA512":
	        template.SignatureAlgorithm = x509.ECDSAWithSHA512
	    case "SHA256WithRSAPSS":
	        template.SignatureAlgorithm = x509.SHA256WithRSAPSS
	    case "SHA384WithRSAPSS":
	        template.SignatureAlgorithm = x509.SHA384WithRSAPSS
	    case "SHA512WithRSAPSS":
	        template.SignatureAlgorithm = x509.SHA512WithRSAPSS
	    // case "PureEd25519":
	    //     template.SignatureAlgorithm = x509.PureEd25519
	    default:
	        log.Fatal("Invalid algo #1")
	}

	f, err := os.Create(*outFlag)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if err := CreateCertificateRequest(f, template, s); err != nil {
		log.Fatal(err)
	}
}

func CreateCertificateRequest(w io.Writer, template *x509.CertificateRequest, signer crypto.Signer) error {
	out, err := x509.CreateCertificateRequest(rand.Reader, template, signer)
	if err != nil {
		return err
	}

	return pem.Encode(w, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: out})
}

type GoogleKMS struct {
	Client        *cloudkms.Service
	keyResourceId string
	publicKey     crypto.PublicKey
}

func NewGoogleKMSSigner(client *cloudkms.Service, keyResourceId string) (*GoogleKMS, error) {
	g := &GoogleKMS{
		keyResourceId: keyResourceId,
		Client:        client,
	}

	err := g.getAsymmetricPublicKey()
	if err != nil {
		return nil, err
	}

	return g, nil
}

// Public returns the Public Key from Google Cloud KMS
func (g *GoogleKMS) Public() crypto.PublicKey {
	return g.publicKey
}

// Sign calls Google Cloud KMS API and performs AsymmetricSign
func (g *GoogleKMS) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	// API expects the digest to be base64 encoded
	digest64 := base64.StdEncoding.EncodeToString(digest)

	var req *cloudkms.AsymmetricSignRequest
    switch *algoFlag {
	    case "SHA256WithRSA":
	        fallthrough
	    case "DSAWithSHA256":
	        fallthrough
	    case "ECDSAWithSHA256":
	        fallthrough
	    case "SHA256WithRSAPSS":
	        req = &cloudkms.AsymmetricSignRequest{
            		Digest: &cloudkms.Digest{
            			Sha256: digest64,
            		},
            	}
	    // case "SHA384WithRSA":
	    //     fallthrough
	    case "ECDSAWithSHA384":
	    //    fallthrough
	    // case "SHA384WithRSAPSS":
	        req = &cloudkms.AsymmetricSignRequest{
            		Digest: &cloudkms.Digest{
            			Sha384: digest64,
            		},
            	}
	    case "SHA512WithRSA":
	        fallthrough
	    case "ECDSAWithSHA512":
	        fallthrough
	    case "SHA512WithRSAPSS":
	        req = &cloudkms.AsymmetricSignRequest{
            		Digest: &cloudkms.Digest{
            			Sha512: digest64,
            		},
            	}
	    default:
	        log.Fatal("Invalid algo #2 ")
	}

	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		AsymmetricSign(g.keyResourceId, req).Context(context.Background()).Do()
	if err != nil {
		return nil, err
	}

	// The response signature is base64 encoded
	return base64.StdEncoding.DecodeString(response.Signature)
}

// getAsymmetricPublicKey pulls public key from Google Cloud KMS API
func (g *GoogleKMS) getAsymmetricPublicKey() error {
	response, err := g.Client.Projects.Locations.KeyRings.CryptoKeys.CryptoKeyVersions.
		GetPublicKey(g.keyResourceId).Context(context.Background()).Do()
	if err != nil {
		return err
	}

	block, _ := pem.Decode([]byte(response.Pem))
	if block == nil || block.Type != "PUBLIC KEY" {
		return fmt.Errorf("not a public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return err
	}

	g.publicKey = publicKey
	return nil
}
