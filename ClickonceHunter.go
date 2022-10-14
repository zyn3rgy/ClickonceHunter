package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
	"net/http"
	"net/url"
	"crypto/tls"
	"io"
	"math/rand"
	"encoding/binary"
	"io/ioutil"
	"net"
	"strconv"
	"regexp"
	"os"
	"os/signal"
	"syscall"
	//"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	//"github.com/yosssi/gohtml"
	"gopkg.in/yaml.v3"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/apigateway"
)

var swissSecrets []string

var clickonceList []string

var yamlConfig YamlConfig

var AwsApiIDs []string


func createRestApiandDeployment(svc *apigateway.APIGateway, stageName string, url string) string{
	//Snippet from: https://github.com/ustayready/fireprox/blob/master/fire.py
	tmpl := `{
		"swagger": "2.0",
		"info": {
		  "version": "bogus_version",
		  "title": "`+stageName+`"
		},
		"basePath": "/",
		"schemes": [
		  "https"
		],
		"paths": {
		  "/": {
			"get": {
			  "parameters": [
				{
				  "name": "proxy",
				  "in": "path",
				  "required.": true,
				  "type": "string"
				},
				{
				  "name": "X-My-X-Forwarded-For",
				  "in": "header",
				  "required": false,
				  "type": "string"
				}
			  ],
			  "responses": {},
			  "x-amazon-apigateway-integration": {
				"uri": "`+url+`/",
				"responses": {
				  "default": {
					"statusCode": "200"
				  }
				},
				"requestParameters": {
				  "integration.request.path.proxy": "method.request.path.proxy",
				  "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
				},
				"passthroughBehavior": "when_no_match",
				"httpMethod": "ANY",
				"cacheNamespace": "irx7tm",
				"cacheKeyParameters": [
				  "method.request.path.proxy"
				],
				"type": "http_proxy"
			  }
			}
		  },
		  "/{proxy+}": {
			"x-amazon-apigateway-any-method": {
			  "produces": [
				"application/json"
			  ],
			  "parameters": [
				{
				  "name": "proxy",
				  "in": "path",
				  "required": true,
				  "type": "string"
				},
				{
				  "name": "X-My-X-Forwarded-For",
				  "in": "header",
				  "required": false,
				  "type": "string"
				}
			  ],
			  "responses": {},
			  "x-amazon-apigateway-integration": {
				"uri": "`+url+`/{proxy}",
				"responses": {
				  "default": {
					"statusCode": "200"
				  }
				},
				"requestParameters": {
				  "integration.request.path.proxy": "method.request.path.proxy",
				  "integration.request.header.X-Forwarded-For": "method.request.header.X-My-X-Forwarded-For"
				},
				"passthroughBehavior": "when_no_match",
				"httpMethod": "ANY",
				"cacheNamespace": "irx7tm",
				"cacheKeyParameters": [
				  "method.request.path.proxy"
				],
				"type": "http_proxy"
			  }
			}
		  }
		}
	  }`

	ir := &apigateway.ImportRestApiInput{
		Body: []byte(tmpl),
	}

	resp, err := svc.ImportRestApi(ir)
	if err != nil {
		panic(err)
	}

	createDeployment := &apigateway.CreateDeploymentInput{
		RestApiId:        resp.Id,
		StageDescription: aws.String("bogus_description"),
		StageName:        aws.String("prod"),
	}

	_, err = svc.CreateDeployment(createDeployment)
	if err != nil {
		panic(err)
	}
	return aws.StringValue(resp.Id)
}


func deleteRestApi(svc *apigateway.APIGateway, rapi string) bool{
	deleteRestApiInput := &apigateway.DeleteRestApiInput{
		RestApiId:		aws.String(rapi),
	}

	_, err := svc.DeleteRestApi(deleteRestApiInput)
	if err != nil {
		return false
		
	}

	return true
}

func GetSwisscowsClickonceURLs(startNum int, requestNonce string, requestSig string, queryString string, awsapigateway string){
	var tr *http.Transport
	if (yamlConfig.HttpProxy != ""){
		proxyUrl, _ := url.Parse("http://"+ yamlConfig.HttpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyUrl),
		}
	} else{
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	timeout := time.Duration(10 * time.Second)

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	} 
	unescaped, _ :=url.QueryUnescape(queryString)	
	fmt.Print("Swisscows Page("+strconv.Itoa(startNum/10)+") Search: "+ unescaped)
	req, err := http.NewRequest("GET", awsapigateway+"web/search?query="+ url.QueryEscape(queryString)+"&offset=" + strconv.Itoa(startNum) + "&itemsCount=10&region=en-US&freshness=All", nil)
	
	req.Header.Set("X-Request-Nonce", requestNonce)
	req.Header.Set("X-Request-Signature", requestSig)
	req.Header.Set("X-My-X-Forwarded-For", randIP())
	if err != nil {
		fmt.Println(err)
	}
	resp, err := client.Do(req)
	
	if err != nil {
		if strings.Contains(err.Error(),"Client.Timeout exceeded"){
			fmt.Println("~TIMEOUT~\n")
			return
		}
		fmt.Println("~UNEXPECTED ERROR~")
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	
	if err != nil {
		log.Fatalln(err)
	}
	respBody := string(b)
	parse := regexp.MustCompile(`"url":"[(http(s)?):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)`)
	valuesFound := parse.FindAllStringSubmatch(respBody, -1)
	for _, value := range valuesFound {
		justString := strings.Join(value, " ")
		parsedString := strings.Split(justString, "\"")[3]
		finalParse := strings.Split(parsedString, " ")[0]
		clickonceList = append(clickonceList, finalParse)
	}		
	
	fmt.Println("Links added - " + strconv.Itoa(len(valuesFound)) + "\n")
}



func randIP() string{
	buf := make([]byte, 4)
	rand.Seed(time.Now().UnixNano())
	ip := rand.Uint32()
	binary.LittleEndian.PutUint32(buf, ip)
	return net.IP(buf).String()
}

func unique(s []string) []string {
    inResult := make(map[string]bool)
    var result []string
    for _, str := range s {
        if _, ok := inResult[str]; !ok {
            inResult[str] = true
            result = append(result, str)
        }
    }
    return result
}

func contains(s []string, e string) bool {
    for _, a := range s {
        if strings.Contains(e, a) {
            return true
        }
    }
    return false
}

func RemoveUnwantedLinks(inputLinks []string) []string {
	unwantedLinks :=  []string{"social.msdn.microsoft.com","www.microsoft.com","docs.microsoft.com", "learn.microsoft.com", "stackoverflow.com"}
    var result []string
    for _, link := range inputLinks {
        if !contains(unwantedLinks, link) {
            result = append(result, link)
        }
    }
    return result
}

func createContext() (context.Context, context.CancelFunc) {
	var opts []func(*chromedp.ExecAllocator)
	if (yamlConfig.HttpProxy != ""){
		opts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("enable-automation", false),
			chromedp.Flag("remote-debugging-port", "9222"),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"),
			chromedp.Flag("proxy-server","http://" + yamlConfig.HttpProxy),
		)
	} else {
		opts = append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.Flag("headless", true),
			chromedp.Flag("enable-automation", false),
			chromedp.Flag("remote-debugging-port", "9222"),
			chromedp.Flag("ignore-certificate-errors", true),
			chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"),
		)
	}
	
	allocCtx, _ := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
	return ctx, cancel
}

func getSwissSecrets(ctx context.Context, startNum int, queryString string){
	headers := map[string]interface{}{
		"X-My-X-Forwarded-For": randIP(),
	}
	linkToVisit := "https://swisscows.com/web?query="+ url.QueryEscape(queryString) +"&offset="+strconv.Itoa(startNum)
	task := chromedp.Tasks{
		network.Enable(),
		network.SetExtraHTTPHeaders(network.Headers(headers)),
		chromedp.Navigate(linkToVisit),
		chromedp.Sleep(1 * time.Second),

		//Example for if DOM needed to be parsed
		/*
		chromedp.ActionFunc(func(ctx context.Context) error {
			node, err := dom.GetDocument().Do(ctx)
			if err != nil {
				return err
			}
			
			out, err := dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
			count := 0
			for !strings.Contains(gohtml.Format(out), "number active") {
				time.Sleep(1 * time.Second)
				fmt.Println("not yet loaded...")
				node, _ := dom.GetDocument().Do(ctx)
				out, _ = dom.GetOuterHTML().WithNodeID(node.NodeID).Do(ctx)
				count++
				if count >= 10 {
					fmt.Println("[!] DOM never loaded expected content - moving on")
					return nil
				}
			}
			//fmt.Println("DOM LOADED")

			parse := regexp.MustCompile(`<a href="[(http(s)?):\/\/(www\.)?a-zA-Z0-9@:%._\+~#=]{2,256}\.[a-z]{2,6}\b([-a-zA-Z0-9@:%_\+.~#?&//=]*)">`)
			valuesFound := parse.FindAllStringSubmatch(out, -1)
			for _, value := range valuesFound {
				justString := strings.Join(value, " ")
				parsedString := strings.Split(justString, "\"")[1]
				fmt.Println(parsedString)
				clickonceList = append(clickonceList, parsedString)
				//fmt.Println("links appended")
			}
			return err
		}),
		*/
		
	}
	if err := chromedp.Run(ctx, task); err != nil {

		log.Fatal(err)
	}
}


func setheaders(host string, headers map[string]interface{}, res *string) chromedp.Tasks {
	return chromedp.Tasks{

		network.SetExtraHTTPHeaders(network.Headers(headers)),


	}
}

func listenForSwissSecrets(ctx context.Context) {

	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
			case *network.EventRequestWillBeSent:
				req := ev.Request
				//Capture the "nonce" and "signature" header values
				if strings.Contains(req.URL, "api.swisscows.com/web/search?query") {
					//fmt.Println("[*] Search request to swisscows identified")
					//fmt.Println(req.Headers["X-Request-Nonce"])
					//fmt.Println(req.Headers["X-Request-Signature"])
					//fmt.Println(req.Headers["X-My-X-Forwarded-For"])
					swissSecrets = nil
					nonce := fmt.Sprintf("%v", req.Headers["X-Request-Nonce"])
					sig :=fmt.Sprintf("%v", req.Headers["X-Request-Signature"])
					swissSecrets = append(swissSecrets, nonce)
					swissSecrets = append(swissSecrets, sig)
					//swissSecrets = append(swissSecrets, req.Headers["X-Request-Signature"])
					//fmt.Printf("t1: %T\n", req.Headers["X-Request-Nonce"])
				}
				
			case *network.EventResponseReceived:
				/*
				resp := ev.Response
				ctx2 := context.Background()
				if strings.Contains(resp.URL, "swisscows.com/api/web/search?query="){
					reqID := ev.RequestID
					fmt.Println(resp.Status)
					body, err := network.GetResponseBody(reqID).Do(ctx2)
					if err != nil {
						panic(err)
					}
					fmt.Println(string(body))
				}
				*/
			
		}


		
	})
}

	
type YamlConfig struct {
	Mode    string `yaml:"Mode"`
	AwsKeys []struct {
		AccessKey string `yaml:"accessKey,omitempty"`
		SecretKey string `yaml:"secretKey,omitempty"`
	} `yaml:"AwsKeys"`
	HttpProxy    string `yaml:"HttpProxy"`
	SearchEngine []struct {
		Google []struct {
			Awsapigateway string   `yaml:"awsapigateway"`
			Iterations    int      `yaml:"iterations"`
			Pages         int      `yaml:"pages"`
			Dorks         []string `yaml:"dorks"`
		} `yaml:"Google,omitempty"`
		Swisscows []struct {
			Awsapigateway string   `yaml:"awsapigateway"`
			Iterations    int      `yaml:"iterations"`
			Pages         int      `yaml:"pages"`
			Dorks         []string `yaml:"dorks"`
		} `yaml:"Swisscows,omitempty"`
	} `yaml:"SearchEngine"`
}

func parseYamlConfig(filename string) YamlConfig{
	yfile, err := ioutil.ReadFile(filename)
    if err != nil {	  
        log.Fatal(err)
    }

    var yamlConfig YamlConfig

    err2 := yaml.Unmarshal(yfile, &yamlConfig)
	
    if err2 != nil {
        log.Fatal(err2)
    }
	return yamlConfig
}


func GetGoogleClickonceURLs(startNum int, queryString string, awsapigateway string){
	var tr *http.Transport
	if (yamlConfig.HttpProxy != ""){
		proxyUrl, _ := url.Parse("http://"+ yamlConfig.HttpProxy)
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyUrl),
		}
	} else{
		tr = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	
	timeout := time.Duration(10 * time.Second)

	client := &http.Client{
		Timeout:   timeout,
		Transport: tr,
	}
	unescaped, _ :=url.QueryUnescape(queryString)	
	fmt.Print("Google Page("+strconv.Itoa(startNum/10)+") Search: "+ unescaped)
	req, err := http.NewRequest("GET", awsapigateway+"search?q="+ url.QueryEscape(queryString)+"&start=" + strconv.Itoa(startNum) + "&filter=0", nil)
	req.Header.Set("User-Agent","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36")
	req.Header.Set("X-My-X-Forwarded-For", randIP())
	if err != nil {
		fmt.Println(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		if strings.Contains(err.Error(),"Client.Timeout exceeded"){
			fmt.Println("~TIMEOUT~\n")
			return
		}
		fmt.Println("~UNEXPECTED ERROR~")
		fmt.Println(err)
		return
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	
	if err != nil {
		log.Fatalln(err)
	}
	respBody := string(b)
	parse := regexp.MustCompile(`url=(http|https):\/\/([\w_-]+(?:(?:\.[\w_-]+)+))([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])`)
	valuesFound := parse.FindAllStringSubmatch(respBody, -1)
	counter := 0
	for _, value := range valuesFound {
		justString := strings.Join(value, " ")
		
		parsedString := strings.Split(justString, "&")[0]
		finalParse := strings.Split(parsedString, "=")[1]
		if !strings.Contains(finalParse, "google.com"){
			clickonceList = append(clickonceList, finalParse)
			counter += 1
		}
	}		

	fmt.Println("Links added - " + strconv.Itoa(counter) + "\n")
}

func CheckMode(config YamlConfig) string{
	if (config.Mode == "provided"){
		if (yamlConfig.SearchEngine[0].Google[0].Awsapigateway == "" && yamlConfig.SearchEngine[1].Swisscows[0].Awsapigateway == ""){
			fmt.Println("\n\nMode in config set to \"PROVIDED\"... but no AWS API endpoints were provided.");
			os.Exit(1);
		}
		fmt.Println("\n\n[+] Mode set in config: PROVIDED")
		fmt.Println("   [*] Parsing Aws API gateway endpoints from config")
		fmt.Println("         " + "https://google.com/ ==> " + yamlConfig.SearchEngine[0].Google[0].Awsapigateway)
		fmt.Println("         " + "https://api.swisscows.com/ ==> " + yamlConfig.SearchEngine[1].Swisscows[0].Awsapigateway)
		
		return "provided"
	} else if (config.Mode == "create"){
		if  (yamlConfig.AwsKeys[0].AccessKey == "" || yamlConfig.AwsKeys[1].SecretKey == ""){
			fmt.Println("\n\nMode in config set to \"CREATE\"... but no AWS keys were provided.");
			os.Exit(1);
		}
		fmt.Println("\n\n[+] Mode set in config: CREATE")
		fmt.Println("   [*] Authentication to AWS using provided key...")
		cfg := aws.NewConfig().WithRegion("us-east-1").WithCredentials(credentials.NewStaticCredentials(yamlConfig.AwsKeys[0].AccessKey, yamlConfig.AwsKeys[1].SecretKey, ""))
		mySession, err := session.NewSession(cfg)
		if err != nil {
			panic(err)
		}
		svc := apigateway.New(mySession, aws.NewConfig().WithRegion("us-east-1"))
		fmt.Println("   [*] Creating API endpoint for Google...")
		googleApi := createRestApiandDeployment(svc, "ClickOnceHunter_Google", "https://www.google.com")
		//----
		yamlConfig.SearchEngine[0].Google[0].Awsapigateway = "https://" +googleApi+ ".execute-api.us-east-1.amazonaws.com/prod/"
		//-----
		AwsApiIDs = append(AwsApiIDs, googleApi)
		fmt.Println("         " + "https://google.com/ ==> " + "https://" +googleApi+ ".execute-api.us-east-1.amazonaws.com/prod/")
		fmt.Println("   [*] Creating API endpoint for SwissCows...")
		
		swisscowsApi := createRestApiandDeployment(svc, "ClickOnceHunter_SwissCows", "https://api.swisscows.com")
		fmt.Println("         " + "https://api.swisscows.com/ ==> " + "https://" +swisscowsApi+ ".execute-api.us-east-1.amazonaws.com/prod/")
		//----
		yamlConfig.SearchEngine[1].Swisscows[0].Awsapigateway = "https://" +swisscowsApi+ ".execute-api.us-east-1.amazonaws.com/prod/"
		//----		
		AwsApiIDs = append(AwsApiIDs, swisscowsApi)

		return "create"
	} else{
		return "unexpected"
	}
}

func cleanup(){
	fmt.Println("\n\n\n\n[+] Cleaning up")
	if (len(AwsApiIDs) >= 1){
		cfg := aws.NewConfig().WithRegion("us-east-1").WithCredentials(credentials.NewStaticCredentials(yamlConfig.AwsKeys[0].AccessKey, yamlConfig.AwsKeys[1].SecretKey, ""))
		mySession, err := session.NewSession(cfg)
		if err != nil {
			panic(err)
		}
		svc := apigateway.New(mySession, aws.NewConfig().WithRegion("us-east-1"))
		for _, apiID := range AwsApiIDs{
			fmt.Print("    [*] Deleting api gateway \"" + apiID +"\"...")
			endpointDeleted := false
			for endpointDeleted == false{
				time.Sleep(3*time.Second)
				deleteResult := deleteRestApi(svc, apiID)
				if (deleteResult == true){
					endpointDeleted = true
				} else{
					fmt.Print(".")
				}
			}
			fmt.Println("  OK")
		}
	}
	fmt.Println()

}

func main() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func(){
		<-c
		cleanup()
		os.Exit(1)
	}()
	
	yamlConfig = parseYamlConfig("config.yml")

	CheckMode(yamlConfig)
	google := yamlConfig.SearchEngine[0].Google[0]
	swisscows := yamlConfig.SearchEngine[1].Swisscows[0]
	fmt.Println("\n[+] Starting....\n\n\n")
	ctx, cancel := createContext()
	defer cancel()

	listenForSwissSecrets(ctx)
	
	for _, dork := range swisscows.Dorks {

		for x := 1; x <= swisscows.Iterations; x++{
			//fmt.Println("ITERATION - " + strconv.Itoa(x))
			for y := 1; y <= swisscows.Pages; y++{
				getSwissSecrets(ctx, (y-1)*10, dork)
				GetSwisscowsClickonceURLs((y-1)*10, swissSecrets[0], swissSecrets[1], dork, swisscows.Awsapigateway)

			} 
		}
	} 
	
	for _, dork := range google.Dorks {

		for x := 1; x <= google.Iterations; x++{
			//fmt.Println("ITERATION - " + strconv.Itoa(x))
			for y := 1; y <= google.Pages; y++{
				GetGoogleClickonceURLs((y-1)*10, dork, google.Awsapigateway)

			} 
		}
	} 
	
	
	fmt.Println("\n")
	uniqueList := RemoveUnwantedLinks(unique(clickonceList))
	for _, link := range uniqueList{
		fmt.Println(link)
	}
	fmt.Print("\n[+] Unique links identified: ")
	fmt.Println(len(uniqueList))
	
	cleanup()

}
