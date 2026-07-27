  FastlyBypass - 70+ техники обхода Fastly WAF (Legacy + Next-Gen / Signal Sciences)
  
  Возможности:
  TLS Impersonation через curl_cffi (chrome126, safari17_5, firefox128)                                                                                             
  IP Spoof (9 заголовков: X-Forwarded-For, X-Real-IP, Client-IP, True-Client-IP, Fastly-Client-IP и др.)                                                            
  Varnish Backend Spoof (Via, X-Varnish, X-Cache, X-Served-By, Age)                                                                                                 
  Fastly-специфичные заголовки (Fastly-Debug, Fastly-SSL, Fastly-POP, Fastly-ASN и др.)                                                                             
  Surrogate/ESI Injection                                                                                                                                           
  JA3/JA4 Header Hints                                                                                                                                              
  HTTP/2 Frame Delay эмуляция                                                                                                                                       
  Content-Type Confusion (16 MIME-типов)                                                                                                                            
  Transfer-Encoding: chunked                                                                                                                                        
  Range Fragment                                                                                                                                                    
  VCL Path Discrepancy (/..;/ для Java/Tomcat)                                                                                                                      
  Case Variation, Double Encoding, Unicode NFKC/NFKD                                                                                                                
  HTTP Parameter Pollution, Null Byte, Path Traversal                                                                                                               
  Payload Padding (>64KB), Multipart Wrapping, Base64, SQL Comments                                                                                                 
  XSS Mutation (svg/img/div), Payload Splitting                                                                                                                     
  Cache-Key Poisoning, Cache Buster                                                                                                                                 
  H2 SETTINGS/Priority Spoof                                                                                                                                        
  и тд.
