$.ajax({type:"GET",url:"https://services.geodan.nl/idp/profile/SAML2/SOAP/ECP",
    headers:{"Accept":"text/html; application/vnd.paos+xml","PAOS":"ver=\"urn:liberty:paos:2003-08\";\"urn:oasis:names:tc:SAML:2.0:profiles:SSO:ecp\""},
    dataType:"text"})
    .done(function(data,statusText,jqXHR){

        var jsonFound = false;/* No error == bad*/
        try{$.parseJSON(data);jsonFound=true;}catch(err){}
        if(!jsonFound){
            var headerStart = data.indexOf("<S:Header>");
            var headerEnd = data.indexOf("</S:Header>");
            var header = data.slice(headerStart,headerEnd+11); /* Get the header */
            var rsStart = header.indexOf("<ecp:RelayState");
            var rsEnd = header.indexOf("</ecp:RelayState>");
            var relayState = header.slice(rsStart,rsEnd+17); /* Get the relay state */
            var samlResponseWithoutHeaderPrefix = data.slice(0,headerStart);
            var samlResponseWithoutHeaderPostfix = data.slice(headerEnd+11);
            var idpRequest = samlResponseWithoutHeaderPrefix+samlResponseWithoutHeaderPostfix; /* Form an xml doc without the header sent to you */
            var base64UserPwd = btoa("tom.van.tilburg@geodan.nl:mixta01"); /* base64 encode the user:pass combination for BASIC AUTH */


            $.ajax({type:"POST",url:"https://services.geodan.nl/idp/profile/SAML2/SOAP/ECP",
                headers:{"Authorization":"Basic "+base64UserPwd},
                dataType:"text",data:idpRequest,timeout:20000})
                .done(function(idpResponse,statusText,jqXHR){
                    var relayStateNSAdjusted = relayState.replace(/S:/g,"soap11:"); /* adjust the xml namespace slightly on the relay state */
                    var idpResponseHeaderStart = idpResponse.indexOf("<soap11:Header>");
                    var idpResponseWithoutHeaderContentPrefix = idpResponse.slice(0,idpResponseHeaderStart+15);
                    var idpResponseHeaderEnd = idpResponse.indexOf("</soap11:Header>");
                    var idpResponseWithoutHeaderContentPostfix = idpResponse.slice(idpResponseHeaderEnd);
                    /* Snip out the header from this response and replace it with the namespace adjusted relay state from the very first response */
                    var spPackage = idpResponseWithoutHeaderContentPrefix+relayStateNSAdjusted+idpResponseWithoutHeaderContentPostfix;


                    $.ajax({type:"POST",url:"https://services.geodan.nl/idp/profile/SAML2/SOAP/ECP",

                        contentType:"application/vnd.paos+xml",dataType:"text",data:spPackage})
                        .done(function(protectedResource,statusText,jqXHR){
                            var json JSON.parse(protectedResource); /* the json var now === the protected resource (in this case json) as a parsed object */
                        })
                        .fail(function(jqXHR,status,error){

                        });
                })
                .fail(function(jqXHR,status,error){

                });
        }else{ /* This can happen if the webview is still logged in for some reason... */
            /* Revoke the session cookie/webcache to esolve this problem */
        }
    })
    .fail(function(jqXHR,status,error){

    });