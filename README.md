
# ClickonceHunter

Tool released in combination with the [Less SmartScreen More Caffeine: ClickOnce (Ab)Use for Trusted Code Execution](https://www.youtube.com/watch?v=cyHxoKvD8Ck)  conference presentation by [0xthirteen](https://twitter.com/0xthirteen) and myself.

Golang web scraper that makes use of both [chromedp](https://github.com/chromedp/chromedp), as well as normal HTTP requests to scrape search engines for published ClickOnce applications. Includes support for AWS API gateway source IP rotation and specifying an HTTP proxy for troubleshooting. Google and Swisscows search engines are currently supported for scraping.


#### Credits

 - [Mike Felch](https://twitter.com/ustayready) - for the [fireprox](https://github.com/ustayready/fireprox) project which allowed for much easier Golang reimplementation
 - [Max Harley](https://twitter.com/0xdab0) - for reimplementing the majority of [fireprox](https://github.com/ustayready/fireprox) in Go to be used in this project


##  Usage 

The functionality of ClickonceHunter is controlled by `config.yml`. There are currently two modes the application will run in:
 - **create** - provide AWS access and secret keys in the config and ClickonceHunter will create AWS API gateway endpoints to use with your search engine requests, then clean them up when it finishes
 - **provided** - create your AWS API gateway endpoint(s) manually or using a tool like [fireprox](https://github.com/ustayready/fireprox) and populate them in the `awsapigateway` field(s) within the config

Values in the `config.yml` file relevant to search engine requests include:
 - **pages** - the amount of pages to request with each of the specified dorks
	 - suggested max values for these are included in a comment within the config
 -  **iterations** - the amount of times to request each page for each of the specified dorks, sometimes unique results will be returned when rotating source IP
	 - anything beyond 3-5 iterations *might* be excessive depending on your use case
 -  **dorks** - targeted searches to be conducted for the specified search engine

Other relevant values in the `config.yml` file include:
 - **http proxy** - no proxy will be used if this value is left blank, and if populated, all the requests will route through the specified proxy and ignore certificate warnings 



## Demo
https://user-images.githubusercontent.com/73311948/195764121-bc924984-82e7-44bf-9474-e7e5923bddb5.mp4






### Implementation Notes

Swisscows scraping has been implemented by making use of the Chrome DevTools protocol with the [chromedp](https://github.com/chromedp/chromedp) project. There are CSRF-like integrity checks included in searches made on the Swisscows search engine, which appear in the form of the `X-Request-Signature` and `X-Request-Nonce` headers. For each dork request, a headless chromium browser is used to browse to the Swisscows landing page using the `getSwissSecrets()` function, and a listening event is created with the `listenForSwissSecrets()` function for when these headers are identified. The headers are then populated for our dork request to pass the integrity check.

#####  ClickonceHunter is not parsing links anymore?!

The HTTP proxy option was added to help the users troubleshoot this for if/when the implemented search engines undoubtedly change their response formatting or API endpoints used to make requests. PRs are welcome!

##### Why no threading though...
Multithreading / goroutine support to the searches made was not implemented. For the purpose of finding published ClickOnce applications, it didn't seem necessary. 


