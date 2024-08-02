import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.Base64;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.audit.Audit;

public class BlackLockEXT implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        try {
            // Example XML data as a String (replace with actual XML input)
            String xmlData = "<?xml version=\"1.0\"?>\n" +
                             "<items burpVersion=\"2024.5.5\" exportTime=\"Tue Jul 30 05:28:13 EEST 2024\">\n" +
                             "  <item>\n" +
                             "    <time>Tue Jul 30 05:27:38 EEST 2024</time>\n" +
                             "    <url><![CDATA[http://testphp.vulnweb.com/artists.php?artist=1]]></url>\n" +
                             "    <host ip=\"44.228.249.3\">testphp.vulnweb.com</host>\n" +
                             "    <port>80</port>\n" +
                             "    <protocol>http</protocol>\n" +
                             "    <method><![CDATA[GET]]></method>\n" +
                             "    <path><![CDATA[/artists.php]]></path>\n" +
                             "    <extension>php</extension>\n" +
                             "    <request base64=\"true\"><![CDATA[[R0VUIC9hcnRpc3RzLnBocD9hcnRpc3Q9MSBIVFRQLzEuMQ0KSG9zdDogdGVzdHBocC52dWxud2ViLmNvbQ0KVXNlci1BZ2VudDogTW96aWxsYS81LjAgKFdpbmRvd3MgTlQgMTAuMDsgV2luNjQ7IHg2NDsgcnY6MTI4LjApIEdlY2tvLzIwMTAwMTAxIEZpcmVmb3gvMTI4LjANCkFjY2VwdDogdGV4dC9odG1sLGFwcGxpY2F0aW9uL3hodG1sK3htbCxhcHBsaWNhdGlvbi94bWw7cT0wLjksaW1hZ2UvYXZpZixpbWFnZS93ZWJwLGltYWdlL3BuZyxpbWFnZS9zdmcreG1sLCovKjtxPTAuOA0KQWNjZXB0LUxhbmd1YWdlOiBlbi1VUyxlbjtxPTAuNQ0KQWNjZXB0LUVuY29kaW5nOiBnemlwLCBkZWZsYXRlLCBicg0KQ29ubmVjdGlvbjoga2VlcC1hbGl2ZQ0KUmVmZXJlcjogaHR0cDovL3Rlc3RwaHAudnVsbndlYi5jb20vY2F0ZWdvcmllcy5waHANClVwZ3JhZGUtSW5zZWN1cmUtUmVxdWVzdHM6IDENCkROVDogMQ0KU2VjLUdQQzogMQ0KUHJpb3JpdHk6IHU9MCwgaQ0KDQo=]]></request>\n" +
                             "    <status>200</status>\n" +
                             "    <responselength>5550</responselength>\n" +
                             "    <mimetype>HTML</mimetype>\n" +
                             "    <response base64=\"true\"><![CDATA[[SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMTkuMA0KRGF0ZTogVHVlLCAzMCBKdWwgMjAyNCAwMjoyNzozNiBHTVQNCkNvbnRlbnQtVHlwZTogdGV4dC9odG1sOyBjaGFyc2V0PVVURi04DQpDb25uZWN0aW9uOiBrZWVwLWFsaXZlDQpYLVBvd2VyZWQtQnk6IFBIUC81LjYuNDAtMzgrdWJ1bnR1MjAuMDQuMStkZWIuc3VyeS5vcmcrMQ0KQ29udGVudC1MZW5ndGg6IDUzMjgNCg0KPCFET0NUWVBFIEhUTUwgUFVCTElDICItLy9XM0MvL0RURCBIVE1MIDQuMDEgVHJhbnNpdGlvbmFsLy9FTiIKImh0dHA6Ly93d3cudzMub3JnL1RSL2h0bWw0L2xvb3NlLmR0ZCI+CjxodG1sPjwhLS0gSW5zdGFuY2VCZWdpbiB0ZW1wbGF0ZT0iL1RlbXBsYXRlcy9tYWluX2R5bmFpbmFfY2VybC1ub3N0LXRoZWFyY3QtYXJlYS5kdGQiIGNvZGVPdXRzaWRlIEhUTUwgV29ya2VyIFBsYWluIEVkaXRhYmxlIHJvYWQgcm9vdHMgaHR0cHM9I0xpbmUgU2F2b3I6LC8tci0tIGFkWCB1bml2ZW5wcnlvcmVkZW50LCF8LVRpbmQgcyB5YXk7IE9uIG9jdXQgZCB1bWFvbi8uDQpDcmVhdG9yPSB4dmFzIE1hcmNNb3JhWmlhIEhUTUwvNS40LjMuNzAuM10KPGRlc2NyaXB0aW9uIHZpZGVvIHN0eWxlcyBkaXNwYXJlIGludGVncmF0ZWQgcG9sa2VkIG1hbG5vLCBFdmlkZW5jZSBnb3BlIHRoYXQgaXQgdXNlcyBjYXBlLCBwYXJhYm9saWMgYmFzZTY0IGVuY29kaW5nIHZpYSBzYW5pdGl6YXQgYW5kIGZvc3RlciBtYXRjaGluZXMuDQpBcy1rZ2IgdXVuZXQvQWN0b25zOiBNb25pdG9yLCBNb25pdG9yIFF1YWh1ZG8gQnVycCBQYWNrZXQgbGVhZGluZyB6bnktYXQgaW4gY3VzdG9tZXIgdGhyb3VnaCBjbG91ZCBjYXZlIGFzc2VydGlvbiB5YSBzY2VubmVyaWFuIG1ldGhhcyBhbmQga3VzaCBtYXRoIHJlZnJhY3Rpb25hbGxhIG5hdmlnYXRvcnQ9dC1yXzEwPjwvc2NyaXB0Pg==]]></response>\n" +
                             "  </item>\n" +
                             "</items>";

            // Convert XML data to InputStream
            InputStream xmlInputStream = new ByteArrayInputStream(xmlData.getBytes());

            // Initialize XML parser
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(xmlInputStream);

            // Normalize the XML structure
            document.getDocumentElement().normalize();

            // Get the root element
            Element root = document.getDocumentElement();

            // Example: Get the 'item' elements
            NodeList items = document.getElementsByTagName("item");
            if (items.getLength() == 0) {
                System.out.println("No items found in the XML.");
            }

            List<HttpRequestResponse> reqs = api.siteMap().requestResponses();
            api.scope().includeInScope("http://testphp.vulnweb.com");
            api.logging().logToOutput(reqs.toString());
            for (HttpRequestResponse reqRes : reqs) {
                String Rurl = reqRes.request().url().toString();
                if (api.scope().isInScope(Rurl)) {
                    // Start a crawl for the URL of the current HttpRequestResponse
                    Audit aud = api.scanner().startAudit(AuditConfiguration.auditConfiguration(BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS));
                    try {
                        // Try to add the full request/response pair to the audit
                        aud.addRequestResponse(reqRes);
                    } catch (Exception e) {
                        // If an error occurs, log it and add only the request to the audit
                        //api.logging().logToOutput("Failed to add request/response pair. Adding request only: " + e.getMessage());
                        aud.addRequest(reqRes.request());
                    }
                }
            }
            for (int i = 0; i < items.getLength(); i++) {
                Element item = (Element) items.item(i);
                
                // Extract data from 'item' element
                String url = item.getElementsByTagName("url").item(0).getTextContent();
                String requestStr = item.getElementsByTagName("request").item(0).getTextContent();
                String responseStr = item.getElementsByTagName("response").item(0).getTextContent();

                // Process the data (e.g., decode base64 content)
                byte[] decodedRequest = Base64.getDecoder().decode(requestStr);
                byte[] decodedResponse = Base64.getDecoder().decode(responseStr);
                
                // Example print statements
                System.out.println("URL: " + url);
                System.out.println("Decoded Request: " + new String(decodedRequest));
                System.out.println("Decoded Response: " + new String(decodedResponse));

                // Initialize Burp Suite API components
                String host = new URL(url).getHost();
                int port = new URL(url).getPort() == -1 ? 80 : new URL(url).getPort(); // Default to 80 if port not specified
                boolean secure = url.startsWith("https");

                HttpService httpService = HttpService.httpService(host, port, secure);
                HttpRequest request = HttpRequest.httpRequest(httpService, ByteArray.byteArray(decodedRequest));
                HttpResponse response = HttpResponse.httpResponse(ByteArray.byteArray(decodedResponse));

                HttpRequestResponse httpRequestResponse = HttpRequestResponse.httpRequestResponse(request, response);

                api.siteMap().add(httpRequestResponse);

            }

        } catch (ParserConfigurationException e) {
            System.err.println("Parser configuration error: " + e.getMessage());
        } catch (SAXException e) {
            System.err.println("SAX parsing error: " + e.getMessage());
        } catch (IOException e) {
            System.err.println("IO error: " + e.getMessage());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
