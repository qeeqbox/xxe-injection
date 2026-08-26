<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/xxe-injection.svg"></p>

## XXE Injection
XML External Entity (XXE) Injection is a security vulnerability that occurs when an application processes untrusted XML input using an XML parser that allows external entities to be resolved. An attacker may manipulate the XML document to cause the application to access local files, make requests to internal or external systems, or consume excessive system resources.

XML (Extensible Markup Language) supports entities that can reference external resources. In secure XML processing, treat untrusted XML strictly as data, and turn off external entity processing unless explicitly required.

## How XXE Injection Works
1. Untrusted XML Input: An application accepts XML data from a user or another untrusted source.
2. External Entity Processing: The XML parser is configured to allow DTDs and resolve external entities.
3. Malicious XML: An attacker submits XML containing a malicious external entity declaration.
4. XML Processing: The parser resolves the external entity while processing the document, potentially causing the application to access resources that were not intended to be exposed.

## XXE Injection Impact
- Local File Disclosure: An attacker may be able to read sensitive files accessible to the application's operating-system account.
- Server-Side Request Forgery (SSRF): An attacker may cause the server to make requests to internal or external resources.
- Sensitive Data Exposure: Information obtained through external entities may be returned in application responses or otherwise exposed.
- Denial of Service: Malicious XML entities can consume excessive CPU or memory resources.
- Internal Network Access: In some environments, XXE can be used to interact with services that are accessible from the server but not directly accessible to the attacker.
- Potential Code Execution: XXE does not inherently provide arbitrary code execution. However, in specific environments, vulnerable parsers, libraries, or integrations may allow XXE to contribute to more serious attacks.

## XXE Injection Mitigation
- Disable External Entity Processing: Configure XML parsers to prevent external entity resolution.
- Disable DTD Processing Where Possible: If the application does not require DTDs, turn off DTD processing entirely.
- Use Secure Parser Configurations: Configure XML libraries according to their secure-processing recommendations and turn off unnecessary XML features.
- Validate XML Input Where Appropriate: Apply appropriate schema validation and input restrictions as an additional security layer. Validation should not replace secure parser configuration.
- Restrict Network Access: Prevent application processes from making unnecessary outbound network connections to reduce the potential impact of SSRF through XXE.
- Apply the Principle of Least Privilege: Run applications with only the file-system, network, and operating-system permissions they require.
- Keep XML Libraries Updated: Use supported versions of XML parsers and related libraries and apply security updates regularly.
- Consider Safer Alternatives: When XML is not required, consider using a data format and parser with fewer dangerous processing features.
- Perform Security Testing: Conduct code reviews and security testing to verify that XML parsers do not resolve external entities or access unauthorized resources.

## XXE Injection Example
Clone this current repo recursively
```sh
git clone --recurse-submodules https://github.com/qeeqbox/xxe-injection
```
Run the webapp using Python
```sh
python3 xxe-injection/vulnerable-web-app/webapp.py
```
Enable the edit option in the config.xml
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/3.png"></p>
Open the webapp in your browser 127.0.0.1:5142
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/1.png"></p>
Use the default credentials (username: admin and password: admin) to login
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/2.png"></p>
In the xsl template file section, change py:function('read', string(/config/config-file)) to py:function(read', 'webapp.py')"/></div>
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/4.png"></p>
Click the validate button
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/5.png"></p>
The webapp reads the webapp.py file and outputs it
<p align="center"> <img src="https://raw.githubusercontent.com/qeeqbox/xxe-injection/main/content/6.png"></p>

When a user hits the validate button, a post request is sent that includes both XML and XSL content to the webapp to validate
## Code
```js
function update_settings(settings,style) {
$.ajax({
    url : "config",
    type : "post",
    data: {"config-xml":settings,"config-xsl":style},
    success:function(data){
      if (data !== 'Error') {
        $('#Settings-results').html(data)
      }
    },
}); 
}

$('#config-button').on('click', function(e) {
e.preventDefault()
update_settings($('#config-xml-text').text(),$('#config-xsl-text').text())
})
````
The post request data is sent to the validate_config() function
```py
elif parsed_url.path == "/config":
    if "config-xml" in post_request_data and "config-xsl" in post_request_data:
        self.send_content(200, [('Content-type', 'text/html')], self.validate_config(post_request_data["config-xml"][0],post_request_data["config-xsl"][0]))
        return
    if "config-timezone" in post_request_data:
        self.send_content(200, [('Content-type', 'text/html')], self.update_config(post_request_data["config-timezone"][0]))
```
The validate_config() function handles the custom Python read function and outputs the requested file from the system
```py
def validate_config(self,settings=False,style=False):
    ret = b""
    try:
        from lxml import etree
        def python_function(context, function_name, argument):
            if function_name == "read":
                with open(path.join(PATH,argument),"r") as f:
                    return f.read()
            raise ValueError("Unsupported function")
        ns = etree.FunctionNamespace("http://qeeqbox.com/python")
        ns["function"] = python_function
        parser = etree.XMLParser(resolve_entities=True)
        config = etree.fromstring(settings.encode("utf-8"), parser)
        xsl_doc = etree.fromstring(style.encode("utf-8"), parser)
        transform = etree.XSLT(xsl_doc)
        ret = etree.tostring(transform(config), encoding="utf-8")
    except Exception as e:
        ret = str(e).encode("utf-8")
    return ret
```
