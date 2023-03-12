## 使用NaïveProxy搭建梯子服务并运用多用户或者多主机名嵌套xray进行分流

## 一、准备工作

### Ⅰ.参考资料

NaïveProxy服务是基于caady的一个代理插件forwardproxy所实现的，如需参阅文档，请访问以下链接：

- caddy：[Welcome — Caddy Documentation (caddyserver.com)](https://caddyserver.com/docs/)
- forwardproxy：[klzgrad/forwardproxy: Forward proxy plugin for the Caddy web server (github.com)](https://github.com/klzgrad/forwardproxy)
- NaïveProxy：[klzgrad/naiveproxy: Make a fortune quietly (github.com)](https://github.com/klzgrad/naiveproxy)

**注意：forwardproxy是第三方插件，caddy本身是不带的，如果要自己构建带forwardproxy的caddy，请参阅官方文档进行编译，本文所使用的caddy来自github“lxhao61”的“integrated-examples”所编译版本**

- lxhao61/integrated-examples：https://github.com/lxhao61/integrated-examples
- chika0801/Xray-install：[chika0801/Xray-install: Xray手动安装教程 (github.com)](https://github.com/chika0801/Xray-install)

Xray-core是v2ray-core的超集，含更好的整体性能和 XTLS 等一系列增强，且完全兼容 v2ray-core 的功能及配置。

- Xray配置指南：[配置文件 | Project X (xtls.github.io)](https://xtls.github.io/config/#概述)
- Loyalsoldier/v2ray-rules-dat：[Loyalsoldier/v2ray-rules-dat: 🦄 🎃 👻 V2Ray 路由规则文件加强版，可代替 V2Ray 官方 geoip.dat 和 geosite.dat，兼容 Shadowsocks-windows、Xray-core、Trojan-Go 和 leaf。Enhanced edition of V2Ray rules dat files, compatible with Xray-core, Shadowsocks-windows, Trojan-Go and leaf. (github.com)](https://github.com/Loyalsoldier/v2ray-rules-dat#geositedat-1)

### Ⅱ.硬件环境

- 一台vps（本文所使用Linux发行版为Ubuntu）

### Ⅲ.其他条件

- 一个域名（本文使用dnspod域名，域名解析与SSL证书均在dnspod解决）

## 二、搭建NaïveProxy服务（caddy）[用于过墙]

- 环境要求：
  - `caddy` caddy带forwardproxy插件
  - `systemctl --version >=232` systemctl版本大于232
  - `sudo` 需要特权

1. 源安装：

   ```
   sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
   ```

   ```
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
   ```

   ```
   curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
   ```

   ```
   sudo apt update
   ```

   ```
   sudo apt install caddy
   ```

   完成后输入caddy就可以查看caddy相关命令，该过程会自动创建caddy用户组和用户。

2. 修改caddy.service

   ```
   vim /lib/systemd/system/caddy.service
   ```

   替换成以下内容（本service仅供参考），主要是为了指定运行程序的用户为caddy：

   ```
   # caddy.service
   #
   # For using Caddy with a config file.
   #
   # Make sure the ExecStart and ExecReload commands are correct
   # for your installation.
   #
   # See https://caddyserver.com/docs/install for instructions.
   #
   # WARNING: This service does not use the --resume flag, so if you
   # use the API to make changes, they will be overwritten by the
   # Caddyfile next time the service is restarted. If you intend to
   # use Caddy's API to configure it, add the --resume flag to the
   # `caddy run` command or use the caddy-api.service file instead.
   
   [Unit]
   Description=Caddy
   Documentation=https://caddyserver.com/docs/
   After=network.target network-online.target
   Requires=network-online.target
   
   [Service]
   Type=notify
   User=caddy
   Group=caddy
   ExecStart=/usr/bin/caddy run --environ --config /etc/caddy/caddy.json
   ExecReload=/usr/bin/caddy reload --config /etc/caddy/caddy.json --force
   TimeoutStopSec=5s
   LimitNOFILE=1048576
   LimitNPROC=512
   PrivateTmp=true
   ProtectSystem=full
   AmbientCapabilities=CAP_NET_BIND_SERVICE
   
   [Install]
   WantedBy=multi-user.target
   ```

   执行命令重载caddy.service

   ```
   systemctl daemon-reload
   ```

3. 替换二进制caddy文件为带forwardproxy的版本：

   到`https://github.com/lxhao61/integrated-examples/releases`下载带`forwardproxy`的`caddy`，然后将其上传至服务器用户目录，然后进行替换：

   ```
   curl -L https://github.com/lxhao61/integrated-examples/releases/latest/download/caddy-$(uname -s)-$(dpkg --print-architecture).tar.gz -o caddy-$(uname -s)-$(dpkg --print-architecture).tar.gz
   ```

   （本文服务器为amd64处理器，如果使用arm之类其他类型处理器，请将其更改）

   ```
   sudo tar -xvpf caddy-Linux-amd64.tar.gz caddy -C ~
   ```

   ```
   sudo mv caddy /usr/bin/
   ```

   执行命令获取caddy所带modules是否带有`forwardproxy`：

   ```
   caddy list-modules | grep forward_proxy
   ```

   返回结果应如下：

   `http.handlers.forward_proxy`

4. 安装ca-certificates

   ```
   sudo apt install ca-certificates
   ```

5. 创建用于存放证书的目录`/etc/ssl/private/`，然后修改证书目录权限：

   ```
   chown -R caddy:caddy /etc/ssl/private/
   ```

6. 创建伪装页面

   ```
   mkdir -p /var/www/html/
   ```

   ```
   cd /var/www/html/
   ```

   放入一个网页（yourwebfolder）到上述目录，然后修改目录权限

   ```
   chown -R caddy:caddy /var/www/html/
   ```

7. 创建并写入caddy配置文件`caddy.json`,文件默认位于`/etc/caddy/caddy.json`：

   ```
   vim /etc/caddy/caddy.json
   ```

   `caddy.json`配置文件见文末。

8. 启动caddy并观察是否正常运行：

   ```
   systemctl restart caddy && systemctl status caddy
   ```

## 三、搭建Xray服务[用于分流]

- 开始安装：

  使用root用户登录

1. 安装xray：

   ```
   bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install --version 1.6.5
   ```

2. 创建并写入Xray的配置文件，文件默认位于`/usr/local/etc/xray/config.json`

   ```
   vim /usr/local/etc/xray/config.json
   ```

   `config.json`配置文件见文末。

3. 下载geosite和geoip

   ```
   curl -Lo /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat && curl -Lo /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat
   ```

   添加crontab计划任务每日6:10更新geo数据(sleep时间请根据自己服务器运行速度与文件下载速度来设定）：

   ```
   echo -e "10 6 * * * systemctl stop xray && sleep 10s && curl -Lo /usr/local/share/xray/geosite.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat && curl -Lo /usr/local/share/xray/geoip.dat https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat && sleep 10s && systemctl start xray" >/var/spool/cron/crontabs/root
   ```

   ```
   /etc/init.d/cron restart
   ```

4. 启动Xray并观察是否正常运行：

   ```
   systemctl restart xray && systemctl status xray
   ```

## *.其他设置及参考配置文件

- 开启BBR和系统优化

  ```
  wget -N --no-check-certificate "https://raw.githubusercontent.com/chiakge/Linux-NetSpeed/master/tcp.sh"
  ```

  ```
  chmod +x tcp.sh
  ```

  ```
  ./tcp.sh
  ```

- **多用户名caddy.json**

  *本配置文件使用了两个naiveproxy用户名进行分流*

  ```
  {
      "admin": {
          "disabled": true
      },
      "logging": {
          "logs": {
              "default": {
                  "writer": {
                      "filename": "/var/log/caddy/error.log",
                      "output": "file"
                  },
                  "level": "DEBUG"
              }
          }
      },
      "apps": {
          "http": {
              "servers": {
                  "srv0": {
                      "listen": [
                          ":443"
                      ],
                      "routes": [//该处直接使用两个handle实现多用户指定不同上游
                          {
                              "handle": [
                                  {
                                      "handler": "forward_proxy",
                                      "hide_ip": true,
                                      "hide_via": true,
                                      "auth_user_deprecated": "netflixuser",
                                      "auth_pass_deprecated": "netflixpasswd",
                                      "probe_resistance": {
                                          "domain": "caddy.localhost"
                                      },
                                      "upstream": "socks5://127.0.0.1:7443"//本文将该上游指定为具有Netflix访问权限上游
                                  }
                              ]
                          },
                          {
                              "handle": [
                                  {
                                      "handler": "forward_proxy",
                                      "hide_ip": true,
                                      "hide_via": true,
                                      "auth_user_deprecated": "commonuser",
                                      "auth_pass_deprecated": "commonpasswd",
                                      "probe_resistance": {
                                          "domain": "caddy.localhost"
                                      },
                                      "upstream": "socks5://127.0.0.1:6443"
                                  }
                              ]
                          },
                          {
                              "match": [
                                  {
                                      "host": [
                                          "your.domain.com"
                                      ]
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "headers",
                                      "response": {
                                          "set": {
                                              "Strict-Transport-Security": [
                                                  "max-age=31536000; includeSubDomains; preload"
                                              ]
                                          }
                                      }
                                  },
                                  {
                                      "handler": "file_server",
                                      "root": "/var/www/html/yourwebfolder"
                                  }
                              ],
                              "terminal": true
                          }
                      ],
                      "tls_connection_policies": [
                          {
                              "match": {
                                  "sni": [
                                      "your.domain.com"
                                  ]
                              },
                              "cipher_suites": [
                                  "TLS_AES_256_GCM_SHA384",
                                  "TLS_AES_128_GCM_SHA256",
                                  "TLS_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                              ],
                              "curves": [
                                  "x25519",
                                  "secp521r1",
                                  "secp384r1",
                                  "secp256r1"
                              ]
                          }
                      ]
                  },
                  "srv1": {
                      "listen": [
                          ":8080"
                      ],
                      "routes": [
                          {
                              "match": [
                                  {
                                      "host": [
                                          "your.domain.com"
                                      ]
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "headers",
                                      "response": {
                                          "set": {
                                              "Strict-Transport-Security": [
                                                  "max-age=31536000; includeSubDomains; preload"
                                              ]
                                          }
                                      }
                                  },
                                  {
                                      "handler": "file_server",
                                      "root": "/var/www/html/yourwebfolder"
                                  }
                              ],
                              "terminal": true
                          }
                      ],
                      "tls_connection_policies": [
                          {
                              "match": {
                                  "sni": [
                                      "your.domain.com"
                                  ]
                              },
                              "cipher_suites": [
                                  "TLS_AES_256_GCM_SHA384",
                                  "TLS_AES_128_GCM_SHA256",
                                  "TLS_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                              ],
                              "curves": [
                                  "x25519",
                                  "secp521r1",
                                  "secp384r1",
                                  "secp256r1"
                              ]
                          }
                      ]
                  },
              }
          },
          "tls": {
              "certificates": {
                  "load_files": [//本文使用的SSL证书是在dnspod申请的诚信亚洲1年证书，因此直接使用加载证书文件的方式，如果需要使用let's encrypt，请参阅caddy官方文档该部分内容
                      {
                          "certificate": "/etc/ssl/private/your.domain.com/your.domain.com_bundle.crt",
                          "key": "/etc/ssl/private/your.domain.com/your.domain.com.key"
                      }
                  ]
              }
          }
      }
  }
  ```

  

- **多主机名caddy.json**

  *本配置文件使用了两个主机名用于创建一个IP上两个不同naiveproxy配置进行分流，分别是sni1和sni2,**要使用多主机名依赖于caddy扩展layer4**:*

  ```
  {
      "admin": {
          "disabled": true
      },
      "logging": {
          "logs": {
              "default": {
                  "writer": {
                      "output": "file",
                      "filename": "/var/log/caddy/access.log"
                  },
                  "level": "ERROR"
              }
          }
      },
      "apps": {
          "layer4": {//使用多域名分流需要此模块支持
              "servers": {
                  "sni": {
                      "listen": [
                          ":443"
                      ],
                      "routes": [
                          {
                              "match": [
                                  {
                                      "tls": {
                                          "sni": [
                                              "sni1.domain.com"//使用二级域名进行分流
                                          ]
                                      }
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "proxy",
                                      "upstreams": [
                                          {
                                              "dial": [
                                                  "127.0.0.1:5443"//转到本地5443端口
                                              ]
                                          }
                                      ]
                                  }
                              ]
                          },
                          {
                              "match": [
                                  {
                                      "tls": {
                                          "sni": [
                                              "sni2.domain.com"//使用二级域名进行分流
                                          ]
                                      }
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "proxy",
                                      "upstreams": [
                                          {
                                              "dial": [
                                                  "127.0.0.1:4443"//转到本地4443端口
                                              ]
                                          }
                                      ]
                                  }
                              ]
                          }
                      ]
                  }
              }
          },
          "http": {
              "servers": {
                  "h1": {
                      "listen": [
                          ":80"
                      ],
                      "routes": [
                          {
                              "handle": [
                                  {
                                      "handler": "static_response",
                                      "headers": {
                                          "Location": [
                                              "https://{http.request.host}{http.request.uri}"
                                          ]
                                      },
                                      "status_code": 301
                                  }
                              ]
                          }
                      ]
                  },
                  "h1h2c": {
                      "listen": [
                          "127.0.0.1:88"
                      ],
                      "routes": [
                          {
                              "handle": [
                                  {
                                      "handler": "headers",
                                      "response": {
                                          "set": {
                                              "Strict-Transport-Security": [
                                                  "max-age=31536000; includeSubDomains; preload"
                                              ]
                                          }
                                      }
                                  },
                                  {
                                      "handler": "file_server",
                                      "root": "/var/www/html/yourwebfolder"
                                  }
                              ]
                          }
                      ],
                      "protocols": [
                          "h1",
                          "h2c"
                      ]
                  },
                  "sni1": {
                      "listen": [
                          "127.0.0.1:5443"//5443端口接收第一层sni1.domain.com域名分流过来的流量
                      ],
                      "routes": [
                          {
                              "handle": [
                                  {
                                      "handler": "forward_proxy",
                                      "hide_ip": true,
                                      "hide_via": true,
                                      "auth_user_deprecated": "sni1",
                                      "auth_pass_deprecated": "passwd",
                                      "probe_resistance": {
                                          "domain": "caddy.localhost"
                                      },
                                      "upstream": "socks5://127.0.0.1:7443"//认证通过的流量转发到后端xray的7443端口
                                  }
                              ]
                          },
                          {
                              "match": [
                                  {
                                      "host": [
                                          "sni1.domain.com"
                                      ]
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "headers",
                                      "response": {
                                          "set": {
                                              "Strict-Transport-Security": [
                                                  "max-age=31536000; includeSubDomains; preload"
                                              ]
                                          }
                                      }
                                  },
                                  {
                                      "handler": "file_server",
                                      "root": "/var/www/html/yourwebfolder"
                                  }
                              ],
                              "terminal": true
                          }
                      ],
                      "tls_connection_policies": [
                          {
                              "certificate_selection": {
                                  "any_tag": [
                                      "tls01"//使用序号为01的证书，注意不要搞错证书
                                  ]
                              },
                              "cipher_suites": [
                                  "TLS_AES_256_GCM_SHA384",
                                  "TLS_AES_128_GCM_SHA256",
                                  "TLS_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                              ],
                              "curves": [
                                  "x25519",
                                  "secp521r1",
                                  "secp384r1",
                                  "secp256r1"
                              ],
                              "alpn": [
                                  "h2",
                                  "http/1.1"
                              ]
                          }
                      ],
                      "protocols": [
                          "h1",
                          "h2"
                      ]
                  },
                  "sni2": {
                      "listen": [
                          "127.0.0.1:4443"//4443端口接收第一层sni2.domain.com域名分流过来的流量
                      ],
                      "routes": [
                          {
                              "handle": [
                                  {
                                      "handler": "forward_proxy",
                                      "hide_ip": true,
                                      "hide_via": true,
                                      "auth_user_deprecated": "sni2",
                                      "auth_pass_deprecated": "passwd",
                                      "probe_resistance": {
                                          "domain": "caddy.localhost"
                                      },
                                      "upstream": "socks5://127.0.0.1:6443"//认证通过的流量转发到后端xray的6443端口
                                  }
                              ]
                          },
                          {
                              "match": [
                                  {
                                      "host": [
                                          "sni2.domain.com"
                                      ]
                                  }
                              ],
                              "handle": [
                                  {
                                      "handler": "headers",
                                      "response": {
                                          "set": {
                                              "Strict-Transport-Security": [
                                                  "max-age=31536000; includeSubDomains; preload"
                                              ]
                                          }
                                      }
                                  },
                                  {
                                      "handler": "file_server",
                                      "root": "/var/www/html/yourwebfolder"
                                  }
                              ],
                              "terminal": true
                          }
                      ],
                      "tls_connection_policies": [
                          {
                              "certificate_selection": {
                                  "any_tag": [
                                      "tls02"//使用序号为02的证书，注意不要搞错证书
                                  ]
                              },
                              "cipher_suites": [
                                  "TLS_AES_256_GCM_SHA384",
                                  "TLS_AES_128_GCM_SHA256",
                                  "TLS_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                                  "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                                  "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
                                  "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
                              ],
                              "curves": [
                                  "x25519",
                                  "secp521r1",
                                  "secp384r1",
                                  "secp256r1"
                              ],
                              "alpn": [
                                  "h2",
                                  "http/1.1"
                              ]
                          }
                      ],
                      "protocols": [
                          "h1",
                          "h2"
                      ]
                  }
              }
          },
          "tls": {
              "certificates": {
                  "load_files": [
                      {
                          "certificate": "/etc/ssl/private/sni1.domain.com/sni1.domain.com_bundle.crt",
                          "key": "/etc/ssl/private/sni1.domain.com/sni1.domain.com.key",
                          "tags": [
                              "tls01"//注意对应域名与证书是否正确
                          ]
                      },
                      {
                          "certificate": "/etc/ssl/private/sni2.domain.com/sni2.domain.com_bundle.crt",
                          "key": "/etc/ssl/private/sni2.domain.com/sni2.domain.com.key",
                          "tags": [
                              "tls02"//注意对应域名与证书是否正确
                          ]
                      }
                  ]
              }
          }
      }
  }
  ```

- config.json:

  xray的配置文件，用于创建inbound用于对接caddy转发过来的流量，充当caddy的上游。本文中caddy和xray对接协议使用socks协议。
  
  ```
  {
      "log": {
          "access": "",
          "error": "",
          "loglevel": "debug"
      },
      "dns": {//通过指定Netflix DNS解析使用落地机DNS，解决明明挂了落地机却时有发生登陆奈飞区为未中转梯的IP所在区的情况，注意要在落地机xray配置入站DNS劫持
          "servers": [
              "localhost",//本机默认DNS
              {
                  "address": "your.netflix.proxy",//你的落地机域名
                  "port": 53,
                  "domains": [
                      "geosite:netflix"
                  ],
                  "clientIP": "your.netflix.proxy.ip"//定义DNS发起客户端IP，此处为1.1.1.1类型格式的IP，不能填写域名
              }
          ],
          "queryStrategy": "UseIP"//视情况使用UseIP还是UseIPv4
      },
      "routing": {
          "domainStrategy": "IPIfNonMatch",
          "domainMatcher": "hybrid",
          "rules": [
              {//劫持所有发送53的DNS请求到Dns-Out，参考https://xtls.github.io/document/level-2/tproxy.html#xray-配置
                  "type": "field",
                  "outboundTag": "Dns-Out",
                  "network": "tcp,udp",
                  "port": 53
              },
              {
                  "type": "field",
                  "outboundTag": "Block",
                  "protocol": [
                      "bittorrent"
                  ]
              },
              {
                  "type": "field",
                  "outboundTag": "Block",
                  "domain": [
                      "geosite:category-ads-all"
                  ]
              },
              {
                  "type": "field",
                  "outboundTag": "Direct",
                  "domain": [
                      "geosite:apple",
                      "geosite:google"
                  ]
              },
              {//指定Netflix类site出口
                  "type": "field",
                  "inboundTag": "Forward-In-NF",
                  "outboundTag": "NetflixRelay",
                  "domain": [
                      "geosite:netflix"
                  ]
              },
              {//指定Netflix类IP出口
                  "type": "field",
                  "inboundTag": "Forward-In-NF",
                  "outboundTag": "NetflixRelay",
                  "ip": [
                      "geoip:netflix"
                  ]
              },
              {//屏蔽任何CN site流量
                  "type": "field",
                  "outboundTag": "Block",
                  "domain": [
                      "geosite:cn",
                      "geosite:cnki"
                  ]
              },
              {//屏蔽任何CN IP流量
                  "type": "field",
                  "outboundTag": "Block",
                  "ip": [
                      "geoip:cn"
                  ]
              }
          ]
      },
      "inbounds": [
          {//接收本机收到的DNS请求，将其通过rule中劫持DNS规则进行劫持，实现对外提供DNS的服务，主要是为了实现落地机DNS查询
              "listen": "0.0.0.0",
              "port": 53,
              "protocol": "dokodemo-door",
              "settings": {
                  "address": "1.1.1.1",//该处IP目标无所谓，因为rule中所有发往53的DNS请求都会被劫持
                  "port": 53,
                  "network": "tcp,udp",
                  "timeout": 5,
                  "followRedirect": false
                },
              "sniffing": {
                  "enabled": true,
                  "destOverride": [
                      "http",
                      "tls",
                      "quic"
                  ]
              },
              "tag": "DNS-In"
          },
          {
              "listen": "127.0.0.1",
              "port": 6443,
              "protocol": "socks",
              "settings": {
                  "auth": "noauth",
                  "udp": true,
                  "ip": "127.0.0.1"
              },
              "sniffing": {
                  "enabled": true,
                  "destOverride": [
                      "http",
                      "tls",
                      "quic"
                  ],
                  "routeOnly": true
              },
              "tag": "Forward-In"//普通流量入站
          },
          {
              "listen": "127.0.0.1",
              "port": 7443,
              "protocol": "socks",
              "settings": {
                  "auth": "noauth",
                  "udp": true,
                  "ip": "127.0.0.1"
              },
              "sniffing": {
                  "enabled": true,
                  "destOverride": [
                      "http",
                      "tls",
                      "quic"
                  ],
                  "routeOnly": true
              },
              "tag": "Forward-In-NF"//Netflix流量入站
          }
      ],
      "outbounds": [
          {
              "protocol": "freedom",
              "tag": "Direct"
          },
          {//DNS出站，具体DNS分流见顶部DNS模块配置，本文使用localhost，即服务器本身默认DNS。
              "protocol": "dns",
              "tag": "Dns-Out"
          },
          {//与下一跳落地机之间的通讯方式，本文使用ss2022，本身已经在墙外，因此优先考虑传输速度。
              "protocol": "shadowsocks",
              "settings": {
                  "servers": [
                      {
                          "address": "your.netflix.proxy",
                          "port": 40000,
                          "method": "2022-blake3-aes-128-gcm",
                          "password": "B50qTd4Rgcexi/vGsp8+Bw=="
                      }
                  ]
              },
              "tag": "NetflixRelay"
          },
          {
              "protocol": "blackhole",
              "settings": {
                  "response": {
                      "type": "http"
                  }
              },
              "tag": "Block"
          }
      ]
  }
  ```
  
  

