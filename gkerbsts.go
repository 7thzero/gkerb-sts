// Copyright 2019 Rion Carter
// Licensed under the terms of the Apache 2.0 license
package main

import (
	"flag"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/russellhaering/gosaml2/types"
	"bytes"
	"encoding/base64"
	"encoding/xml"
	"gopkg.in/jcmturner/gokrb5.v7/client"
	"gopkg.in/jcmturner/gokrb5.v7/config"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
	"gopkg.in/jcmturner/gokrb5.v7/spnego"
	"io/ioutil"
	"log"
	"golang.org/x/net/html"
	"net/http"
	"os"
	"os/user"
	"path"
	"strings"
	"time"
)

/*
 *
 * Lightly tested on Ubuntu 18.04.
 *
 * You might need to make a change to disable systemd-resolved to get around a DNS lookup issue pertinent to Golang:
 *  https://askubuntu.com/questions/907246/how-to-disable-systemd-resolved-in-ubuntu
 *  https://github.com/cloudflare/cloudflared/issues/75#issuecomment-469904183
 *  https://github.com/golang/go/issues/27546
 *
 */
func main() {
	idpUrl := flag.String("IdentityIrpPath", "https://adfs.dummy-domain.tld/adfs/ls/IdpInitiatedSignOn.aspx?loginToRp=urn:amazon:webservices", "Set the IdentityIRP. This is a dummy value by default to show common URL usage")
	region := flag.String("AwsRegion", "us-east-1", "Set the AWS Region pertinent to your use case")
	dnsLookupKdc := flag.Bool("DnsLookupKdc", true, "Set this to 'false' if you want to use a hard-coded KDC instead of performing DNS resolution")
	autoSetAwsCreds := flag.Bool("ConfigureAwsCredentials", true, "Set to 'false' to write the credentials file to the working directory instead of overwriting the credentials stored in the user directory (~/.aws/credentials)")
	flag.Parse()
	//
	// Need to know who I am to load the kerberos credentials cache
	user, _ := user.Current()

	//
	// Load the credentials cache
	cCachePath := "/tmp/krb5cc_"+user.Uid
	cache, errCache := credentials.LoadCCache(cCachePath)
	if errCache != nil{
		log.Println("Unable to load the specified kerberos credentials cache: " + cCachePath)
		log.Println(errCache)
	}

	//
	// If this fails to load, be sure to remove configurations specific to 'Heimdal Kerberos' in /etc/krb5.conf
	// ex:
	// # The following libdefaults parameters are only for Heimdal Kerberos.
	//			fcc-mit-ticketflags = true
	//
	//[realm]
	//		ATHENA.MIT.EDU = {
	//				kdc = kerberos.mit.edu
	//				kdc = kerberos-1.mid.edu
	//				kdc = kerberos-2.mid.edu:88
	//				admin_server = kerberos.mit.edu
	//				default_domain = mit.edu
	//		}
	//	etc...
	//
	config, errLoadConfig := config.Load("/etc/krb5.conf")
	if errLoadConfig != nil{
		log.Println("Unable to load kerberos client configuration. Does your krb5.conf file include directives specific to Heimdal Kerberos? Those settings cause the kerb config parser to fail")
		log.Println(errLoadConfig)
	}

	//
	// If we are configured to do a DNS lookup to find the KDC, this document describes the relevant process for how it works
	// https://docs.bmc.com/docs/ServerAutomation/85/configuring-after-installation/administering-security/implementing-authentication/implementing-active-directory-kerberos-authentication/configuring-a-bmc-server-automation-client-for-ad-kerberos-authentication/locating-the-active-directory-kdc-for-the-client-s-domain
	//
	// * nslookup -type=srv _kerberos._tcp.<CLIENT_DOMAIN>		(CLIENT_DOMAIN is the domain that your workstation or server is joined to)
	//
	// * The results of this query come back looking something like this (for a hypothetical workwork.work domain):
	//
	// $ nslookup -type=srv _kerberos._tcp.workwork.work
	// ;; Truncated, retrying in TCP mode.
	// Server:	172.16.0.2
	// Address: 172.16.0.2#53
	//
	// _kerberos._tcp.workwork.work     service = 0 100 88 sorepaw169i.workwork.work
	// _kerberos._tcp.workwork.work     service = 0 100 88 sorepaw165i.workwork.work
	// _kerberos._tcp.workwork.work     service = 0 100 88 sorepaw161i.workwork.work
	// _kerberos._tcp.workwork.work     service = 0 100 88 sorepaw163i.workwork.work
	// _kerberos._tcp.workwork.work     service = 0 100 88 sorepaw166i.workwork.work

	//
	// Set the DNS Lookup in accordance with configured flags
	config.LibDefaults.DNSLookupKDC = *dnsLookupKdc

	//
	// Build a kerberos client from the credentials cache
	client, errClient := client.NewClientFromCCache(cache, config)
	if errClient != nil{
		log.Println("Unable to get a kerberos client from cached credentials")
		log.Println(errClient)
		return
	}

	//
	// Get an HTTP Client that can handle kerberos authentication
	spnClient := spnego.NewClient(client, nil, "")

	//
	// Try to authenticate to ADFS via Kerberos
	//	Set the User-Agent to try and force SPNEGO authentication (User agent is _CRITIAL_ to get this to work!)
	log.Println("***\n*** Configured to use this ADFS/IDP URL: ", *idpUrl)
	adfsAuthReq, _ := http.NewRequest("GET", *idpUrl, nil)
	adfsAuthReq.Header.Add("User-Agent", "Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko")
	resp, errResp := spnClient.Do(adfsAuthReq)
	if errResp != nil{
		log.Println("Error trying to access url: " + adfsAuthReq.URL.Path, "\nError:", errResp)
		return
	}

	var respBytes []byte
	if resp.Body != nil{
		respBytes, _ = ioutil.ReadAll(resp.Body)
		resp.Body.Close()
	}

	//
	// Extract the SAML token from the response body
	//	html -> body > form (named "hiddenform") -> input (named "SAMLResponse").value
	tokenized := html.NewTokenizer(bytes.NewReader(respBytes))
	samlTokenEncoded := ""
	for{
		token := tokenized.Next()

		//
		// Be sure to get the `.Token()` only once per token or weirdness will ensue!
		t := tokenized.Token()
		done := false
		switch{
		case token == html.ErrorToken:
			// Issue tokenizing a response
			log.Println(tokenized.Err())
			break
		case token == html.EndTagToken:
			// Explicit check for close of HTML document
			if t.Data == "html"{
				done = true
			}
			break
		case token == html.StartTagToken || token == html.SelfClosingTagToken:
			//log.Println(t.Data, t)  // Commenting out debug logging

			// The SAML response is in an input tag
			if t.Data == "input" {
				// Build a dictionary of the attributes
				attributes := make(map[string]string)
				for _, attribute := range t.Attr{
					attributes[attribute.Key] = attribute.Val
				}

				// Ensure we get the right input tag
				if attributes["name"] != "SAMLResponse"{
					continue
				}

				if _, exists := attributes["value"]; exists{
					samlTokenEncoded = attributes["value"]
					done = true
					break
				}
			}
		}

		if done{
			break
		}
	}


	//
	// 1-Parse the returned SAML Assertion										(handler.py line 91)
	samlTokenBytes, errSamlTokenBytes := base64.StdEncoding.DecodeString(samlTokenEncoded)
	if errSamlTokenBytes != nil{
		log.Println("Unable to decode SAML assertion from ADFS")
		log.Println(errSamlTokenBytes)
		return
	}

	samlResponse := &types.Response{}
	errUnmarshal := xml.Unmarshal(samlTokenBytes, &samlResponse)
	if errUnmarshal != nil{
		log.Println("Unable to unmarshal SAML response. Error: " + errUnmarshal.Error())
	}

	//
	// 2-Extract the authorized roles
	//
	//	Comment from kerb-sts python:
	//		# Note the format of the attribute value should be role_arn,principal_arn
	//		# but lots of blogs list it as principal_arn,role_arn so let's reverse
	//		# them if needed
	var roles []AWSRole
	for _, ass := range samlResponse.Assertions{
		// SAML returns a list of attributes
		for _, att := range ass.AttributeStatement.Attributes{
			// We are only interested in looping over the AWS Roles to get the ARNs
			if att.Name == "https://aws.amazon.com/SAML/Attributes/Role"{
				for _, roleSAML := range att.Values{
					roles = append(roles, AWSRole{
						SAML: roleSAML.Value,
					})
				}
			}
		}
	}

	//
	// 3- Go through each returned role and get temporary tokens for each one
	sess, errGetSess := session.NewSession(&aws.Config{
		Region:aws.String("us-east-1"),
	})
	if errGetSess != nil{
		log.Println("Unable to get empty session for STS AssumeRoleWithSAML. Error: " + errGetSess.Error())
		return
	}

	stsSvc := sts.New(sess)

	var assumedRoles []*sts.AssumeRoleWithSAMLOutput
	for _, role := range roles{
		credReq := &sts.AssumeRoleWithSAMLInput{
			RoleArn: role.ARN(),
			PrincipalArn: role.ProviderARN(),
			SAMLAssertion:&samlTokenEncoded,
		}

		assumedRole, errAssumeRoleSAML := stsSvc.AssumeRoleWithSAML(credReq)
		if errAssumeRoleSAML != nil{
			log.Println("Unable to assume role/get creds for: " + *role.Name()+"\nError: " + errAssumeRoleSAML.Error())
		}

		if assumedRole.AssumedRoleUser != nil {
			assumedRoles = append(assumedRoles, assumedRole)
			log.Println("Generated: ", assumedRole.AssumedRoleUser.GoString())
		}
	}


	//
	// 5- Write out the credentials to the ~/.aws/credentials file
	/*
		[default]
		region =
		aws_access_key_id =
		output = json
		aws_security_token =
		aws_session_token =
		aws_secret_access_key =
		aws_role_arn =
		aws_session_expires_utc =

		[u-auditor]
		region =
		aws_access_key_id =
		output = json
		aws_security_token =
		aws_session_token =
		aws_secret_access_key =
		aws_role_arn =
		aws_session_expires_utc =

		[other-role]
		region =
		aws_access_key_id =
		output = json
		aws_security_token =
		aws_session_token =
		aws_secret_access_key =
		aws_role_arn =
		aws_session_expires_utc =
	*/
	var credentials strings.Builder
	for _, role := range assumedRoles{
		arnSplit := strings.Split(*role.AssumedRoleUser.Arn, "/")
		sectionName := arnSplit[1]

		credentials.WriteString("["+sectionName+"]\n")
		credentials.WriteString("region = "+*region+"\n")
		credentials.WriteString("aws_access_key_id = "+*role.Credentials.AccessKeyId+"\n")
		credentials.WriteString("output = json\n")
		credentials.WriteString("aws_security_token = "+*role.Credentials.SessionToken+"\n")
		credentials.WriteString("aws_session_token = "+*role.Credentials.SessionToken+"\n")
		credentials.WriteString("aws_secret_access_key = "+*role.Credentials.SecretAccessKey+"\n")
		credentials.WriteString("aws_role_arn = "+*role.AssumedRoleUser.Arn+"\n")
		credentials.WriteString("aws_session_expires_utc = "+role.Credentials.Expiration.UTC().Format(time.RFC3339)+"\n\n")
	}

	// Write out the file
	var awsCredsFile string
	if *autoSetAwsCreds{
		// **Overwrite ~/.aws/credentials
		awsDir := path.Join(user.HomeDir, ".aws")
		awsCredsFile = path.Join(awsDir, "credentials")
		os.MkdirAll(awsDir, 0770)
	} else {
		// Place the credentials file in the working directory where this executable is running from
		awsCredsFile = "credentials"
	}
	credentialsStr := credentials.String()
	ioutil.WriteFile(awsCredsFile, []byte(credentialsStr), 0640)

	log.Println("Credentials file written to: ", awsCredsFile)
}

//
// Example Role ARN
// arn:aws:iam::123456789012:saml-provider/MFAProtectedProvider,arn:aws:iam::123456789012:role/dba-role
type AWSRole struct{
	SAML string
	arn string
	arnProvider string
	name string
}


// Get the ARN from the SAML output
func (r *AWSRole) ARN() *string{

	if r.arn != ""{
		return &r.arn
	}

	// Ensure struct values are set correctly
	r.parseSAML()

	return &r.arn
}

// Get the Provider ARN from the SAML output
func (r *AWSRole) ProviderARN() *string{

	if r.arnProvider != ""{
		return &r.arnProvider
	}

	// Ensure struct values are set correctly
	r.parseSAML()

	return &r.arnProvider
}

// Get the Provider ARN from the SAML output
func (r *AWSRole) Name() *string{

	if r.name != ""{
		return &r.arnProvider
	}

	// Ensure struct values are set correctly
	r.parseSAML()

	return &r.arnProvider
}

// Ensure values are properly set
func (r *AWSRole) parseSAML(){
	// Set the provider arn and role arn
	split := strings.Split(r.SAML, ",")
	r.arnProvider = split[0]
	r.arn = split[1]

	// Ensure get the role name
	nameSplit := strings.Split(r.arn, "/")
	r.name = nameSplit[1]
}