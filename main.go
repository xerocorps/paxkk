package main

import (
        "bufio"
        "crypto/tls"
        "encoding/json"
        "errors"
        "flag"
        "fmt"
        "log"
        "net/http"
        "net/url"
        "os"
        "regexp"
        "strings"
        "sync"
        "time"
        "net"
        "runtime"

        "github.com/gocolly/colly/v2"
)

type Result struct {
        Source string
        URL    string
        Where  string
}

var headers map[string]string
var keywords []string
var mutex = &sync.Mutex{}
// Thread safe map
var sm sync.Map

var (
        // Cache for storing the results of IP checks
        ipCheckCache = make(map[string]bool)
        // Mutex to control concurrent access to the cache
        cacheMutex sync.RWMutex
        // Precomputed list of *net.IPNet for banned ranges
        bannedIPNets []*net.IPNet
        // Once to ensure the initialization is done only once
        once sync.Once
)

func main() {
        inside := flag.Bool("i", false, "Only crawl inside path")
        threads := flag.Int("t", 8, "Number of threads to utilise.")
        depth := flag.Int("d", 2, "Depth to crawl.")
        maxSize := flag.Int("size", -1, "Page size limit, in KB.")
        insecure := flag.Bool("insecure", false, "Disable TLS verification.")
        subsInScope := flag.Bool("subs", false, "Include subdomains for crawling.")
        showJson := flag.Bool("json", false, "Output as JSON.")
        showSource := flag.Bool("s", false, "Show the source of URL based on where it was found. E.g. href, form, script, etc.")
        showWhere := flag.Bool("w", false, "Show at which link the URL is found.")
        unique := flag.Bool(("u"), false, "Show only unique urls.")
        proxy := flag.String(("proxy"), "", "Proxy URL. E.g. -proxy http://127.0.0.1:8080")
        timeout := flag.Int("timeout", -1, "Maximum time to crawl each URL from stdin, in seconds.")
        disableRedirects := flag.Bool("dr", false, "Disable following HTTP redirects.")
        keywordFile := flag.String("k", "", "Path to a wordlist file containing keywords.")

        flag.Parse()

        // Open the file for writing or append if it exists
        outputFile, err := os.OpenFile("matched_urls.txt", os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0644)
        if err != nil {
            log.Fatal(err)
        }
        defer outputFile.Close()

        // Create a writer for the output file
        const bufferSize = 10 * 1024 * 1024 // 20MB
        outputWriter := bufio.NewWriterSize(outputFile, bufferSize)

    if *keywordFile != "" {
        keywords, err = loadKeywordsFromFile(*keywordFile)
        if err != nil {
            fmt.Fprintln(os.Stderr, "Error loading keywords from file:", err)
            os.Exit(1)
        }
    }

        if *proxy != "" {
                os.Setenv("PROXY", *proxy)
        }
        proxyURL, _ := url.Parse(os.Getenv("PROXY"))

        // Check for stdin input
        stat, _ := os.Stdin.Stat()
        if (stat.Mode() & os.ModeCharDevice) != 0 {
                fmt.Fprintln(os.Stderr, "No urls detected. Hint: cat urls.txt | hakrawler")
                os.Exit(1)
        }

        results := make(chan string, *threads)
        go func() {
                // get each line of stdin, push it to the work channel
                s := bufio.NewScanner(os.Stdin)
                for s.Scan() {
                        url := s.Text()
                        hostname, err := extractHostname(url)
                        if err != nil {
                                log.Println("Error parsing URL:", err)
                                continue
                        }

                        allowed_domains := []string{hostname}
                        // if "Host" header is set, append it to allowed domains
                        if headers != nil {
                                if val, ok := headers["Host"]; ok {
                                        allowed_domains = append(allowed_domains, val)
                                }
                        }

                        // Instantiate default collector
                        c := colly.NewCollector(
                                // default user agent header
                                colly.UserAgent("Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0"),
                                // set custom headers
                                // colly.Headers(headers),
                                // limit crawling to the domain of the specified URL
                                // colly.AllowedDomains(allowed_domains...),
                                // set MaxDepth to the specified depth
                                colly.MaxDepth(*depth),
                                colly.DisallowedDomains("github.com"),
                                // specify Async for threading
                                colly.Async(true),
                        )

                        // set a page size limit
                        if *maxSize != -1 {
                                c.MaxBodySize = *maxSize * 1024
                        }

                        // if -subs is present, use regex to filter out subdomains in scope.
                        if *subsInScope {
                            c.AllowedDomains = nil
                            c.URLFilters = []*regexp.Regexp{regexp.MustCompile(".*((https?:\\/\\/)?([a-zA-Z0-9-]+\\.)?" + strings.ReplaceAll(hostname, ".", "\\.") + "((#|\\/|\\?).*)?)")}
                        }

                        // If `-dr` flag provided, do not follow HTTP redirects.
                        if *disableRedirects {
                                c.SetRedirectHandler(func(req *http.Request, via []*http.Request) error {
                                        return http.ErrUseLastResponse
                                })
                        }
                        // Set parallelism
                        c.Limit(&colly.LimitRule{DomainGlob: "*", Parallelism: *threads})


                        // // Print every href found, and visit it
                        // c.OnHTML("a[href]", func(e *colly.HTMLElement) {
                        //      link := e.Attr("href")
                        //      abs_link := e.Request.AbsoluteURL(link)
                        //      if strings.Contains(abs_link, url) || !*inside {

                        //              printResult(link, "href", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //              e.Request.Visit(e.Request.AbsoluteURL(link))
                        //      }
                        //      // Before making a request print "Visiting ..."
                        //      c.OnRequest(func(r *colly.Request) {
                        //              fmt.Println("Visiting-------------HREF", e.Request.AbsoluteURL(link))
                        //      })
                        //      c.OnResponse(func(r *colly.Response) {
                        //              log.Println("response received", r.StatusCode, e.Request.AbsoluteURL(link))
                        //      })
                        // })

                        c.OnHTML("video[src], audio[src], embed[src], track[src], area[href], applet[archive], base[href], bgsound[src], body[background], link[type='application/rss+xml'], link[type='application/atom+xml'], link[type='application/xml'], img[src*='.webp'], link[rel='manifest'], meta[property^='og:'], meta[name^='twitter:'], a[href$='.xml'], *[src^='data:'], script[src^='ws://'], script[src^='wss://'], frame[src], frameset[frameborder='1'], a[href], script[src], form[action], script, link[rel=stylesheet], [src], iframe, img, button[href], a[href], form[action], select", func(e *colly.HTMLElement) {
                                src := e.Attr("src")
                                href := e.Attr("href")
                                archive := e.Attr("archive")
                                background := e.Attr("background")
                                feedURL := e.Attr("href")
                                webpURL := e.Attr("src")
                                manifestURL := e.Attr("href")
                                property := e.Attr("property")
                                name := e.Attr("name")
                                content := e.Attr("content")
                                sitemapURL := e.Attr("href")
                                dataURI := e.Attr("src")
                                websocketURL := e.Attr("src")
                                frameURL := e.Attr("src")
                                link := e.Attr("href")
                                absLink := e.Request.AbsoluteURL(link)
                                jsCode := e.Text
                                urls := extractURLsFromJS(jsCode)
                                cssURL := e.Attr("href")
                                srcURL := e.Attr("src")
                                link2 := e.Attr("href")

                                if src != "" {
                                        printResult(src, "video", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                if src != "" {
                                        printResult(src, "audio", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                if src != "" {
                                        printResult(src, "embed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                if src != "" {
                                        printResult(src, "track", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                if href != "" {
                                        printResult(href, "area", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(href))
                                }

                                if archive != "" {
                                        printResult(archive, "applet", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(archive))
                                }

                                if href != "" {
                                        printResult(href, "base", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(href))
                                }

                                if src != "" {
                                        printResult(src, "bgsound", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                if background != "" {
                                        printResult(background, "body-background", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(background))
                                }

                                if feedURL != "" {
                                        printResult(feedURL, "feed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(feedURL))
                                }

                                if webpURL != "" {
                                        printResult(webpURL, "webp-image", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(webpURL))
                                }

                                if manifestURL != "" {
                                        printResult(manifestURL, "manifest", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(manifestURL))
                                }

                                if property != "" && content != "" {
                                        printResult(content, "social-media-"+property, *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(content))
                                } else if name != "" && content != "" {
                                        printResult(content, "social-media-"+name, *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(content))
                                }

                                if sitemapURL != "" {
                                        printResult(sitemapURL, "sitemap", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(sitemapURL))
                                }

                                if dataURI != "" {
                                        printResult(dataURI, "data-uri", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(dataURI))
                                }

                                if websocketURL != "" {
                                        printResult(websocketURL, "websocket", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(websocketURL))
                                }

                                if frameURL != "" {
                                        printResult(frameURL, "frame", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(frameURL))
                                }

                                if strings.Contains(absLink, url) || !*inside {
                                        printResult(link, "href", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(link))
                                }

                                printResult(e.Attr("src"), "script", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                printResult(e.Attr("action"), "form", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)

                                for _, url := range urls {
                                        printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(url))
                                }

                                printResult(cssURL, "css", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)

                                if srcURL != "" {
                                        printResult(srcURL, "embedded", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(srcURL))
                                }

                                if link2 != "" && (strings.HasPrefix(link2, "http://") || strings.HasPrefix(link2, "https://")) {
                                        printResult(link2, "interactive", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(link2))
                                }
                        })

                        // Extract URLs from all HTML elements and attributes
                        c.OnHTML("*", func(e *colly.HTMLElement) {
                                body := e.Text

                                // Extract URLs using the custom regular expression pattern
                                urls := extractURLsWithCustomPattern(body)
                                for _, url := range urls {
                                        printResult(url, "custom_REGEX", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(url))
                                }

                                // Check for href attribute
                                href := e.Attr("href")
                                if href != "" {
                                        printResult(href, "href", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(href))
                                }

                                // Check for src attribute
                                src := e.Attr("src")
                                if src != "" {
                                        printResult(src, "src", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(src))
                                }

                                //Check for data attributes that may contain URLs
                                e.ForEach("[data-*]", func(_ int, el *colly.HTMLElement) {
                                        dataAttr := el.Text
                                        if dataAttr != "" {
                                                printResult(dataAttr, "data", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                                e.Request.Visit(e.Request.AbsoluteURL(dataAttr))
                                        }
                                })

                                // Check for content attribute in meta tags
                                if e.Name == "meta" {
                                        content := e.Attr("content")
                                        if content != "" {
                                                printResult(content, "meta", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                                e.Request.Visit(e.Request.AbsoluteURL(content))
                                        }
                                }

                                // Check for URLs in inline JavaScript code
                                if e.Name == "script" {
                                        jsCode := e.Text
                                        urls := extractURLsFromJS(jsCode)
                                        for _, url := range urls {
                                                printResult(url, "jscode", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                                e.Request.Visit(e.Request.AbsoluteURL(url))
                                        }
                                }

                                // Check for URLs in CSS files
                                if e.Name == "link" && e.Attr("rel") == "stylesheet" {
                                        cssURL := e.Attr("href")
                                        printResult(cssURL, "css", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                        e.Request.Visit(e.Request.AbsoluteURL(cssURL))
                                }

                                //Check for custom data attributes that may contain URLs
                                e.ForEach("[data-custom-*]", func(_ int, el *colly.HTMLElement) {
                                        customDataAttr := el.Text
                                        if customDataAttr != "" {
                                                printResult(customDataAttr, "custom-data", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                                                e.Request.Visit(e.Request.AbsoluteURL(customDataAttr))
                                        }
                                })

                        })

                        // c.OnHTML("video[src], audio[src], embed[src], track[src], area[href], applet[archive], base[href], bgsound[src], body[background], link[type='application/rss+xml'], link[type='application/atom+xml'], link[type='application/xml'], img[src*='.webp'], link[rel='manifest'], meta[property^='og:'], meta[name^='twitter:'], a[href$='.xml'], *[src^='data:'], script[src^='ws://'], script[src^='wss://'], frame[src], frameset[frameborder='1']", func(e *colly.HTMLElement) {
                        //      switch {
                        //      case e.Name == "video":
                        //              src := e.Attr("src")
                        //              if src != "" {
                        //                      printResult(src, "video", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(src))
                        //              }
                        //      case e.Name == "audio":
                        //              src := e.Attr("src")
                        //              if src != "" {
                        //                      printResult(src, "audio", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(src))
                        //              }
                        //      case e.Name == "embed":
                        //              src := e.Attr("src")
                        //              if src != "" {
                        //                      printResult(src, "embed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(src))
                        //              }
                        //      case e.Name == "track":
                        //              src := e.Attr("src")
                        //              if src != "" {
                        //                      printResult(src, "track", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(src))
                        //              }
                        //      case e.Name == "area":
                        //              href := e.Attr("href")
                        //              if href != "" {
                        //                      printResult(href, "area", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(href))
                        //              }
                        //      case e.Name == "applet":
                        //              archive := e.Attr("archive")
                        //              if archive != "" {
                        //                      printResult(archive, "applet", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(archive))
                        //              }
                        //      case e.Name == "base":
                        //              href := e.Attr("href")
                        //              if href != "" {
                        //                      printResult(href, "base", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(href))
                        //              }
                        //      case e.Name == "bgsound":
                        //              src := e.Attr("src")
                        //              if src != "" {
                        //                      printResult(src, "bgsound", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(src))
                        //              }
                        //      case e.Name == "body":
                        //              background := e.Attr("background")
                        //              if background != "" {
                        //                      printResult(background, "body-background", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(background))
                        //              }
                        //      case e.Name == "link":
                        //              feedURL := e.Attr("href")
                        //              switch {
                        //              case strings.Contains(e.Attr("type"), "application/rss+xml"):
                        //                      printResult(feedURL, "feed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(feedURL))
                        //              case strings.Contains(e.Attr("type"), "application/atom+xml"):
                        //                      printResult(feedURL, "feed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(feedURL))
                        //              case strings.Contains(e.Attr("type"), "application/xml"):
                        //                      printResult(feedURL, "feed", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(feedURL))
                        //              }
                        //      case e.Name == "img" && strings.Contains(e.Attr("src"), ".webp"):
                        //              webpURL := e.Attr("src")
                        //              if webpURL != "" {
                        //                      printResult(webpURL, "webp-image", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(webpURL))
                        //              }
                        //      case e.Name == "link" && e.Attr("rel") == "manifest":
                        //              manifestURL := e.Attr("href")
                        //              if manifestURL != "" {
                        //                      printResult(manifestURL, "manifest", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(manifestURL))
                        //              }
                        //      case e.Name == "meta" && (strings.HasPrefix(e.Attr("property"), "og:") || strings.HasPrefix(e.Attr("name"), "twitter:")):
                        //              property := e.Attr("property")
                        //              name := e.Attr("name")
                        //              content := e.Attr("content")
                        //              if property != "" && content != "" {
                        //                      printResult(content, "social-media-"+property, *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(content))
                        //              } else if name != "" && content != "" {
                        //                      printResult(content, "social-media-"+name, *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(content))
                        //              }
                        //      case e.Name == "a" && strings.HasSuffix(e.Attr("href"), ".xml"):
                        //              sitemapURL := e.Attr("href")
                        //              if sitemapURL != "" {
                        //                      printResult(sitemapURL, "sitemap", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(sitemapURL))
                        //              }
                        //      case strings.HasPrefix(e.Attr("src"), "data:"):
                        //              dataURI := e.Attr("src")
                        //              if dataURI != "" {
                        //                      printResult(dataURI, "data-uri", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(dataURI))
                        //              }
                        //      case strings.HasPrefix(e.Attr("src"), "ws://") || strings.HasPrefix(e.Attr("src"), "wss://"):
                        //              websocketURL := e.Attr("src")
                        //              if websocketURL != "" {
                        //                      printResult(websocketURL, "websocket", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(websocketURL))
                        //              }
                        //      case e.Name == "frame" || (e.Name == "frameset" && e.Attr("frameborder") == "1"):
                        //              frameURL := e.Attr("src")
                        //              if frameURL != "" {
                        //                      printResult(frameURL, "frame", *showSource, *showWhere, *showJson, results, e, outputWriter, outputFile)
                        //                      e.Request.Visit(e.Request.AbsoluteURL(frameURL))
                        //              }
                        //      }
                        // })

                        // On request completion, free up memory
                        c.OnScraped(func(r *colly.Response) {
                                // Free memory
                                runtime.GC()
                        })

                        // add the custom headers
                        if headers != nil {
                                c.OnRequest(func(r *colly.Request) {
                                        for header, value := range headers {
                                                r.Headers.Set(header, value)
                                        }
                                })
                        }

                        if *proxy != "" {
                                // Skip TLS verification for proxy, if -insecure specified
                                c.WithTransport(&http.Transport{
                                        Proxy:           http.ProxyURL(proxyURL),
                                        TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
                                })
                        } else {
                                // Skip TLS verification if -insecure flag is present
                                c.WithTransport(&http.Transport{
                                        TLSClientConfig: &tls.Config{InsecureSkipVerify: *insecure},
                                })
                        }

                        if *timeout == -1 {
                                // Check if URL is alive before scraping
                                if !isURLAlive(url, *timeout) {
                                        log.Println("[URL not reachable] " + url)
                                        continue
                                }
                                // Start scraping
                                c.Visit(url)
                                // Wait until threads are finished
                                c.Wait()
                        } else {
                                finished := make(chan int, 1)

                                go func() {
                                        // Check if URL is alive before scraping
                                        if isURLAlive(url, *timeout) {
                                                // Start scraping if URL is alive
                                                c.Visit(url)
                                                // Wait until threads are finished
                                                c.Wait()
                                        } else {
                                                log.Println("[URL not reachable] " + url)
                                        }
                                        finished <- 0
                                }()

                                select {
                                case _ = <-finished: // the crawling finished before the timeout
                                        close(finished)
                                        continue
                                case <-time.After(time.Duration(*timeout) * time.Second): // timeout reached
                                        log.Println("[timeout] " + url)
                                        continue
                                }
                        }

                }
                if err := s.Err(); err != nil {
                        fmt.Fprintln(os.Stderr, "reading standard input:", err)
                }
                close(results)
        }()

        w := bufio.NewWriter(os.Stdout)
        defer w.Flush()
        if *unique {
                for res := range results {
                        if isUnique(res) {
                                fmt.Fprintln(w, res)
                        }
                }
        }
        for res := range results {
                fmt.Fprintln(w, res)
        }

}

// parseHeaders does validation of headers input and saves it to a formatted map.
func parseHeaders(rawHeaders string) error {
        if rawHeaders != "" {
                if !strings.Contains(rawHeaders, ":") {
                        return errors.New("headers flag not formatted properly (no colon to separate header and value)")
                }

                headers = make(map[string]string)
                rawHeaders := strings.Split(rawHeaders, ";;")
                for _, header := range rawHeaders {
                        var parts []string
                        if strings.Contains(header, ": ") {
                                parts = strings.SplitN(header, ": ", 2)
                        } else if strings.Contains(header, ":") {
                                parts = strings.SplitN(header, ":", 2)
                        } else {
                                continue
                        }
                        headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
                }
        }
        return nil
}

// extractHostname() extracts the hostname from a URL and returns it
func extractHostname(urlString string) (string, error) {
        u, err := url.Parse(urlString)
        if err != nil || !u.IsAbs() {
                return "", errors.New("Input must be a valid absolute URL")
        }

        return u.Hostname(), nil
}

func printResult(link string, sourceName string, showSource bool, showWhere bool, showJson bool, results chan string, e *colly.HTMLElement, outputWriter *bufio.Writer, outputFile *os.File) {
    // Check if keywords are provided and if any of them are present in the URL
    if len(keywords) == 0 || containsKeyword(link, keywords) {
        result := e.Request.AbsoluteURL(link)
        whereURL := e.Request.URL.String()
        if result != "" {
            if showJson {
                where := ""
                if showWhere {
                    where = whereURL
                }
                bytes, _ := json.Marshal(Result{
                    Source: sourceName,
                    URL:    result,
                    Where:  where,
                })
                result = string(bytes)
            } else if showSource {
                result = "[" + sourceName + "] " + result
            }

            if showWhere && !showJson {
                result = "[" + whereURL + "] " + result
            }

            // Lock the mutex before writing to the file
            mutex.Lock()

            // Save URLs containing keywords to the file
            if len(keywords) == 0 || containsKeyword(result, keywords) {
                _, err := outputWriter.WriteString(result + "\n")
                if err != nil {
                    log.Println("Error writing URL to file:", err)
                }
                outputWriter.Flush() // Flush immediately to save to the file
            }

            // Unlock the mutex
            defer mutex.Unlock()

            // If timeout occurs before goroutines are finished, recover from panic that may occur when attempting writing to results to the closed results channel
            defer func() {
                if err := recover(); err != nil {
                    return
                }
            }()

            // Send the result to the channel
            results <- result
        }
    }
}

// Function to check if any keyword is present in the URL
func containsKeyword(url string, keywords []string) bool {
    for _, keyword := range keywords {
        if strings.Contains(url, keyword) {
            return true
        }
    }
    return false
}

// returns whether the supplied url is unique or not
func isUnique(url string) bool {
        _, present := sm.Load(url)
        if present {
                return false
        }
        sm.Store(url, true)
        return true
}

func extractURLsFromJS(jsCode string) []string {
    // Regular expression pattern to match URLs in JavaScript code
    regex := regexp.MustCompile(`(?i)(?:(?:https?|ftp|smtp|unknown|sftp|file|data|telnet|ssh|ws|wss|git|svn|gopher):\/\/)(?:(?:[^\s:@'"]+(?::[^\s:@'"]*)?@)?(?:[_A-Z0-9.-]+|\[[_A-F0-9]*:[_A-F0-9:]+\])(?::\d{1,5})?)(?:\/[^\s'"]*)?(?:\?[^\s'"]*)?(?:#[^\s'"]*)?`)
    matches := regex.FindAllString(jsCode, -1)
    
    // Deduplicate the matches (if needed)
    uniqueURLs := make(map[string]bool)
    for _, match := range matches {
        uniqueURLs[match] = true
    }
    
    // Convert unique URLs to a slice
    var urls []string
    for url := range uniqueURLs {
        urls = append(urls, url)
    }
    
    return urls
}

func extractURLsWithCustomPattern(body string) []string {
    // Define your custom regular expression pattern here
    customRegexPattern := `(?i)(?:(?:https?|ftp|smtp|unknown|sftp|file|data|telnet|ssh|ws|wss|git|svn|gopher):\/\/)(?:(?:[^\s:@'"]+(?::[^\s:@'"]*)?@)?(?:[_A-Z0-9.-]+|\[[_A-F0-9]*:[_A-F0-9:]+\])(?::\d{1,5})?)(?:\/[^\s'"]*)?(?:\?[^\s'"]*)?(?:#[^\s'"]*)?`
    
    // Regular expression pattern to match URLs based on the custom pattern
    regex := regexp.MustCompile(customRegexPattern)
    matches := regex.FindAllString(body, -1)
    
    // Deduplicate the matches (if needed)
    uniqueURLs := make(map[string]bool)
    for _, match := range matches {
        uniqueURLs[match] = true
    }
    
    // Convert unique URLs to a slice
    var urls []string
    for url := range uniqueURLs {
        urls = append(urls, url)
    }
    
    return urls
}

func loadKeywordsFromFile(filename string) ([]string, error) {
    file, err := os.Open(filename)
    if err != nil {
        return nil, err
    }
    defer file.Close()

    var keywords []string
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        keyword := scanner.Text()
        keywords = append(keywords, keyword)
    }

    if err := scanner.Err(); err != nil {
        return nil, err
    }

    return keywords, nil
}

// Function to initialize banned IP ranges
func initializeBannedIPRanges() {
        bannedCIDRs := []string{
                "5.9.0.0/16", "5.75.128.0/17", "5.161.0.0/21", "5.161.164.0/22", "5.161.168.0/21",
                "5.161.238.0/23", "5.222.0.0/15", "23.88.0.0/17", "37.27.0.0/16", "45.145.227.0/24",
                "46.4.0.0/16", "46.62.128.0/17", "49.12.0.0/15", "65.21.0.0/16", "65.108.0.0/15",
                "77.42.0.0/17", "78.46.0.0/15", "78.138.62.0/24", "85.10.192.0/18", "88.99.0.0/16",
                "88.198.0.0/16", "89.167.0.0/17", "91.99.0.0/16", "91.107.128.0/17", "91.190.240.0/21",
                "91.233.8.0/22", "94.130.0.0/16", "95.216.0.0/15", "116.202.0.0/15", "128.140.0.0/17",
                "135.181.0.0/16", "136.243.0.0/16", "138.199.128.0/17", "138.201.0.0/16", "142.132.128.0/17",
                "144.76.0.0/16", "148.251.0.0/16", "157.90.0.0/16", "157.180.0.0/17", "159.69.0.0/16",
                "162.55.0.0/16", "167.233.0.0/16", "167.235.0.0/16", "168.119.0.0/16", "171.25.225.0/24",
                "176.9.0.0/16", "178.63.0.0/16", "178.212.75.0/24", "185.12.64.0/22", "185.50.120.0/23",
                "185.107.52.0/22", "185.126.28.0/22", "185.157.83.0/24", "185.157.176.0/22", "185.171.224.0/22",
                "185.189.228.0/22", "185.213.45.0/24", "185.216.237.0/24", "185.226.99.0/24", "185.228.8.0/23",
                "185.242.76.0/24", "185.253.111.0/24", "188.34.128.0/17", "188.40.0.0/16", "188.245.0.0/16",
                "193.25.170.0/23", "193.110.6.0/23", "193.163.198.0/24", "194.42.180.0/22", "194.42.184.0/22",
                "194.62.106.0/24", "195.60.226.0/24", "195.201.0.0/16", "195.248.224.0/24", "197.242.84.0/22",
                "201.131.3.0/24", "204.29.146.0/24", "213.133.96.0/19", "213.232.193.0/24", "213.239.192.0/18",
                "216.55.108.0/22",
        }

        // Parse CIDRs once and store in the list
        for _, cidr := range bannedCIDRs {
                _, ipNet, err := net.ParseCIDR(cidr)
                if err != nil {
                        log.Printf("[ERROR]: Invalid CIDR notation %s: %v\n", cidr, err)
                        continue
                }
                bannedIPNets = append(bannedIPNets, ipNet)
        }
}

// Function to check if an IP address falls within a banned range
func isBannedIP(ip net.IP) bool {
        once.Do(initializeBannedIPRanges) // Ensure CIDRs are initialized only once

        // Use a read lock for concurrent cache access
        cacheMutex.RLock()
        if result, exists := ipCheckCache[ip.String()]; exists {
                cacheMutex.RUnlock()
                return result
        }
        cacheMutex.RUnlock()

        // Check if IP is in any banned range
        for _, ipNet := range bannedIPNets {
                if ipNet.Contains(ip) {
                        cacheMutex.Lock()
                        ipCheckCache[ip.String()] = true
                        cacheMutex.Unlock()
                        log.Printf("[FILTERED]: IP %s is in a banned range: %s\n", ip, ipNet)
                        return true
                }
        }

        // Store result in the cache
        cacheMutex.Lock()
        ipCheckCache[ip.String()] = false
        cacheMutex.Unlock()
        return false
}

// Function to check if the URL should be processed based on its DNS resolution and banned IP ranges
func shouldProcessURL(host string) bool {
        ips, err := net.LookupIP(host)
        if err != nil {
                log.Printf("[DNS ERROR]: Unable to resolve host %s: %v\n", host, err)
                return false
        }

        if len(ips) == 0 {
                log.Printf("[NO IP ADDRESSES]: No IP addresses found for host %s\n", host)
                return false
        }

        var wg sync.WaitGroup
        resultChan := make(chan bool, len(ips))

        // Perform concurrent IP checks
        for _, ip := range ips {
                wg.Add(1)
                go func(ip net.IP) {
                        defer wg.Done()
                        if isBannedIP(ip) {
                                resultChan <- true
                        } else {
                                resultChan <- false
                        }
                }(ip)
        }

        wg.Wait()
        close(resultChan)

        // If any IP is in the banned range, return false
        for result := range resultChan {
                if result {
                        return false
                }
        }
        return true
}

// Function to check if a URL is alive by making a HEAD request
func isURLAlive(url string, timeout int) bool {
        host, err := extractHostname(url)
        if err != nil {
                log.Printf("[INVALID URL]: %s\n", url)
                return false
        }

        if !shouldProcessURL(host) {
                log.Printf("[SKIPPED URL]: %s due to banned IP range or restricted domain resolution\n", url)
                return false
        }

        maxRetries := 4
        for i := 0; i < maxRetries; i++ {
                client := http.Client{
                        Timeout: time.Duration(timeout) * time.Second,
                }
                resp, err := client.Head(url)
                if err != nil {
                        log.Printf("[NETWORK ERROR]: %s, Retry #%d\n", url, i+1)
                        time.Sleep(15 * time.Second)
                        continue
                }
                defer resp.Body.Close()

                if resp.StatusCode >= 200 && resp.StatusCode < 400 {
                        return true
                } else if resp.StatusCode == http.StatusTooManyRequests {
                        log.Printf("[RATE LIMITING]: %s, Status Code: %d, Retry #%d\n", url, resp.StatusCode, i+1)
                        time.Sleep(20 * time.Second)
                } else if resp.StatusCode >= 500 {
                        log.Printf("[RETRYING]: %s - Status: %d\n", url, resp.StatusCode)
                        time.Sleep(10 * time.Second)
                } else if resp.StatusCode == 404 || resp.StatusCode == 403 || resp.StatusCode == 401 || resp.StatusCode == 400 {
                        log.Printf("[SKIPPING]: %s - Status: %d\n", url, resp.StatusCode)
                        return false
                } else {
                        log.Printf("[HTTP STATUS]: %s, Status Code: %d, Retry #%d\n", url, resp.StatusCode, i+1)
                        time.Sleep(5 * time.Second)
                }
        }

        log.Printf("[URL UNREACHABLE]: %s\n", url)
        return false
}
