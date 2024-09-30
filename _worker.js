// @ts-nocheck
// <!--GAMFC-->version base on commit 43fad05dcdae3b723c53c226f8181fc5bd47223e, time is 2023-06-22 15:20:02 UTC<!--GAMFC-END-->.
// @ts-ignore
// https://github.com/bia-pain-bache/BPB-Worker-Panel

import { connect } from 'cloudflare:sockets';

// How to generate your own UUID:
// https://www.uuidgenerator.net/
let userID = '4420c1b6-cbdc-4521-8a80-08aaf2ad5737';

// https://www.nslookup.io/domains/bpb.yousef.isegaro.com/dns-records/
const proxyIPs= ['bpb.yousef.isegaro.com'];
const defaultHttpPorts = ['80', '8080', '2052', '2082', '2086', '2095', '8880'];
const defaultHttpsPorts = ['443', '8443', '2053', '2083', '2087', '2096'];
let proxyIP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
let dohURL = 'https://cloudflare-dns.com/dns-query';
let trojanPassword = `bpb-trojan`;
// https://emn178.github.io/online-tools/sha224.html
// https://www.atatus.com/tools/sha224-to-hash
let hashPassword = 'b5d0a5f7ff7aac227bc68b55ae713131ffdf605ca0da52cce182d513';
let panelVersion = '2.5.9';

if (!isValidUUID(userID)) throw new Error(`Invalid UUID: ${userID}`);
if (!isValidSHA224(hashPassword)) throw new Error(`Invalid Hash password: ${hashPassword}`);

export default {
    /**
     * @param {import("@cloudflare/workers-types").Request} request
     * @param {{UUID: string, PROXYIP: string, DNS_RESOLVER_URL: string}} env
     * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
     * @returns {Promise<Response>}
     */
    async fetch(request, env, ctx) {
        try {          
            userID = env.UUID || userID;
            proxyIP = env.PROXYIP || proxyIP;
            dohURL = env.DNS_RESOLVER_URL || dohURL;
            trojanPassword = env.TROJAN_PASS || trojanPassword;
            hashPassword = env.HASH_PASS || hashPassword;
            const upgradeHeader = request.headers.get('Upgrade');
            const url = new URL(request.url);
            
            if (!upgradeHeader || upgradeHeader !== 'websocket') {
                
                const searchParams = new URLSearchParams(url.search);
                const host = request.headers.get('Host');
                const client = searchParams.get('app');

                switch (url.pathname) {

                    case '/cf':
                        return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json;charset=utf-8',
                            },
                        });
                        
                    case '/warp-keys':

                        const Auth = await Authenticate(request, env); 
                        if (!Auth) return new Response('Unauthorized', { status: 401 });

                        if (request.method === 'POST' && request.headers.get('content-type') === 'application/json') {
                            try {
                                const warpKeys = await request.json();
                                const warpPlusError = await fetchWgConfig(env, warpKeys);
                                if (warpPlusError) {
                                    return new Response(warpPlusError, { status: 400 });
                                } else {
                                    return new Response('Warp configs updated successfully', { status: 200 });
                                }
                            } catch (error) {
                                console.log(error);
                                return new Response(`An error occurred while updating Warp configs! - ${error}`, { status: 500 });
                            }

                        } else {
                            return new Response('Unsupported request', { status: 405 });
                        }

                    case `/sub/${userID}`:

                        if (client === 'sfa') {
                            const BestPingSFA = await getSingboxConfig(env, host, client, false);
                            return new Response(JSON.stringify(BestPingSFA, null, 4), { 
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'Surrogate-Control': 'no-store'
                                }
                            });                            
                        }
                        
                        if (client === 'clash') {
                            const BestPingClash = await getClashConfig(env, host, false);
                            return new Response(JSON.stringify(BestPingClash, null, 4), { 
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'Surrogate-Control': 'no-store'
                                }
                            });                            
                        }

                        const normalConfigs = await getNormalConfigs(env, host, client);
                        return new Response(normalConfigs, { 
                            status: 200,
                            headers: {
                                'Content-Type': 'text/plain;charset=utf-8',
                                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                'Surrogate-Control': 'no-store'
                            }
                        });                        

                    case `/fragsub/${userID}`:
  
                        let fragConfigs = client === 'hiddify'
                            ? await getSingboxConfig(env, host, client, false, true)
                            : (await getFragmentConfigs(env, host));

                        return new Response(JSON.stringify(fragConfigs, null, 4), { 
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json;charset=utf-8',
                                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                'Surrogate-Control': 'no-store'
                            }
                        });

                    case `/warpsub/${userID}`:

                        if (client === 'clash') {
                            const clashWarpConfigs = await getClashConfig(env, host, true);
                            return new Response(JSON.stringify(clashWarpConfigs, null, 4), { 
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'Surrogate-Control': 'no-store'
                                }
                            });                            
                        }
                        
                        if (client === 'singbox' || client === 'hiddify') {
                            const singboxWarpConfigs = await getSingboxConfig(env, host, client, true);
                            return new Response(JSON.stringify(singboxWarpConfigs, null, 4), { 
                                status: 200,
                                headers: {
                                    'Content-Type': 'application/json;charset=utf-8',
                                    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                    'Surrogate-Control': 'no-store'
                                }
                            });                            
                        }

                        const warpConfig = await getXrayWarpConfigs(env, client);
                        return new Response(JSON.stringify(warpConfig, null, 4), { 
                            status: 200,
                            headers: {
                                'Content-Type': 'application/json;charset=utf-8',
                                'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
                                'Surrogate-Control': 'no-store'
                            }
                        });

                    case '/panel':

                        if (typeof env.bpb !== 'object') {
                            const errorPage = renderErrorPage('KV Dataset is not properly set!', null, true);
                            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
                        }

                        const pwd = await env.bpb.get('pwd');
                        const isAuth = await Authenticate(request, env); 
                        
                        if (request.method === 'POST') {     
                            if (!isAuth) return new Response('Unauthorized', { status: 401 });
                            const formData = await request.formData();
                            const isReset = formData.get('resetSettings') === 'true';             
                            isReset 
                                ? await updateDataset(env, null, true) 
                                : await updateDataset(env, formData);

                            return new Response('Success', { status: 200 });
                        }
                        
                        if (pwd && !isAuth) return Response.redirect(`${url.origin}/login`, 302);
                        const proxySettings = await env.bpb.get('proxySettings', {type: 'json'});
                        const isUpdated = panelVersion === proxySettings?.panelVersion;
                        if (!proxySettings || !isUpdated) await updateDataset(env);
                        const homePage = await renderHomePage(env, host);

                        return new Response(homePage, {
                            status: 200,
                            headers: {
                                'Content-Type': 'text/html',
                                'Access-Control-Allow-Origin': url.origin,
                                'Access-Control-Allow-Methods': 'GET, POST',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                                'X-Content-Type-Options': 'nosniff',
                                'X-Frame-Options': 'DENY',
                                'Referrer-Policy': 'strict-origin-when-cross-origin'
                            }
                        });
                                                      
                    case '/login':

                        if (typeof env.bpb !== 'object') {
                            const errorPage = renderErrorPage('KV Dataset is not properly set!', null, true);
                            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
                        }

                        const loginAuth = await Authenticate(request, env);
                        if (loginAuth) return Response.redirect(`${url.origin}/panel`, 302);

                        let secretKey = await env.bpb.get('secretKey');
                        if (!secretKey) {
                            secretKey = generateSecretKey();
                            await env.bpb.put('secretKey', secretKey);
                        }

                        if (request.method === 'POST') {
                            const password = await request.text();
                            const savedPass = await env.bpb.get('pwd');

                            if (password === savedPass) {
                                const jwtToken = generateJWTToken(password, secretKey);
                                const cookieHeader = `jwtToken=${jwtToken}; HttpOnly; Secure; Max-Age=${7 * 24 * 60 * 60}; Path=/; SameSite=Strict`;
                                
                                return new Response('Success', {
                                    status: 200,
                                    headers: {
                                      'Set-Cookie': cookieHeader,
                                      'Content-Type': 'text/plain',
                                    }
                                });        
                            } else {
                                return new Response('Method Not Allowed', { status: 405 });
                            }
                        }
                        
                        const loginPage = await renderLoginPage();

                        return new Response(loginPage, {
                            status: 200,
                            headers: {
                                'Content-Type': 'text/html',
                                'Access-Control-Allow-Origin': url.origin,
                                'Access-Control-Allow-Methods': 'GET, POST',
                                'Access-Control-Allow-Headers': 'Content-Type, Authorization',
                                'X-Content-Type-Options': 'nosniff',
                                'X-Frame-Options': 'DENY',
                                'Referrer-Policy': 'strict-origin-when-cross-origin'
                            }
                        });
                    
                    case '/logout':
                                    
                        return new Response('Success', {
                            status: 200,
                            headers: {
                                'Set-Cookie': 'jwtToken=; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                                'Content-Type': 'text/plain'
                            }
                        });        

                    case '/panel/password':

                        const oldPwd = await env.bpb.get('pwd');
                        let passAuth = await Authenticate(request, env);
                        if (oldPwd && !passAuth) return new Response('Unauthorized!', { status: 401 });           
                        const newPwd = await request.text();
                        if (newPwd === oldPwd) return new Response('Please enter a new Password!', { status: 400 });
                        await env.bpb.put('pwd', newPwd);

                        return new Response('Success', {
                            status: 200,
                            headers: {
                                'Set-Cookie': 'jwtToken=; Path=/; Secure; SameSite=None; Expires=Thu, 01 Jan 1970 00:00:00 GMT',
                                'Content-Type': 'text/plain',
                            }
                        });

                    default:
                        // return new Response('Not found', { status: 404 });
                        url.hostname = 'www.speedtest.net';
                        url.protocol = 'https:';
                        request = new Request(url, request);
                        return await fetch(request);
                }
            } else {
                return url.pathname.startsWith('/tr') ? await trojanOverWSHandler(request) : await vlessOverWSHandler(request);
            }
        } catch (err) {
            /** @type {Error} */ let e = err;
            const errorPage = renderErrorPage('Something went wrong!', e.message.toString(), false);
            return new Response(errorPage, { status: 200, headers: {'Content-Type': 'text/html'}});
        }
    },
};

/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request) {
    /** @type {import("@cloudflare/workers-types").WebSocket[]} */
    // @ts-ignore
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = "";
    let portWithRandomLog = "";
    const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

    /** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
    let remoteSocketWapper = {
        value: null,
    };
    let udpStreamWrite = null;
    let isDns = false;

    // ws --> remote
    readableWebSocketStream
    .pipeTo(
        new WritableStream({
            async write(chunk, controller) {
                if (isDns && udpStreamWrite) {
                    return udpStreamWrite(chunk);
                }
                if (remoteSocketWapper.value) {
                    const writer = remoteSocketWapper.value.writable.getWriter();
                    await writer.write(chunk);
                    writer.releaseLock();
                    return;
                }

                const {
                    hasError,
                    message,
                    portRemote = 443,
                    addressRemote = "",
                    rawDataIndex,
                    vlessVersion = new Uint8Array([0, 0]),
                    isUDP,
                } = await processVlessHeader(chunk, userID);
                address = addressRemote;
                portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp " : "tcp "} `;
                if (hasError) {
                    // controller.error(message);
                    throw new Error(message); // cf seems has bug, controller.error will not end stream
                    // webSocket.close(1000, message);
                    return;
                }
                // if UDP but port not DNS port, close it
                if (isUDP) {
                    if (portRemote === 53) {
                        isDns = true;
                    } else {
                        // controller.error('UDP proxy only enable for DNS which is port 53');
                        throw new Error("UDP proxy only enable for DNS which is port 53"); // cf seems has bug, controller.error will not end stream
                        return;
                    }
                }
                // ["version", "附加信息长度 N"]
                const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
                const rawClientData = chunk.slice(rawDataIndex);

                // TODO: support udp here when cf runtime has udp support
                if (isDns) {
                    const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
                    udpStreamWrite = write;
                    udpStreamWrite(rawClientData);
                    return;
                }

                handleTCPOutBound(
                    request,
                    remoteSocketWapper,
                    addressRemote,
                    portRemote,
                    rawClientData,
                    webSocket,
                    vlessResponseHeader,
                    log
                );
            },
            close() {
                log(`readableWebSocketStream is close`);
            },
            abort(reason) {
                log(`readableWebSocketStream is abort`, JSON.stringify(reason));
            },
        })
    )
    .catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });

    return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

/**
 * Checks if a given UUID is present in the API response.
 * @param {string} targetUuid The UUID to search for.
 * @returns {Promise<boolean>} A Promise that resolves to true if the UUID is present in the API response, false otherwise.
 */
async function checkUuidInApiResponse(targetUuid) {
    // Check if any of the environment variables are empty
  
    try {
        const apiResponse = await getApiResponse();
        if (!apiResponse) {
            return false;
        }
        const isUuidInResponse = apiResponse.users.some((user) => user.uuid === targetUuid);
        return isUuidInResponse;
    } catch (error) {
        console.error("Error:", error);
        return false;
    }
}

async function trojanOverWSHandler(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWapper = {
      value: null,
    };
    let udpStreamWrite = null;

    readableWebSocketStream
        .pipeTo(
            new WritableStream({
                async write(chunk, controller) {
                    if (udpStreamWrite) {
                        return udpStreamWrite(chunk);
                    }

                    if (remoteSocketWapper.value) {
                        const writer = remoteSocketWapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const {
                        hasError,
                        message,
                        portRemote = 443,
                        addressRemote = "",
                        rawClientData,
                    } = await parseTrojanHeader(chunk);

                    address = addressRemote;
                    portWithRandomLog = `${portRemote}--${Math.random()} tcp`;

                    if (hasError) {
                        throw new Error(message);
                        return;
                    }

                    handleTCPOutBound(request, remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, false, log);
                },
                close() {
                    log(`readableWebSocketStream is closed`);
                },
                abort(reason) {
                    log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
                },
            })
        )
        .catch((err) => {
            log("readableWebSocketStream pipeTo error", err);
        });

        return new Response(null, {
        status: 101,
        // @ts-ignore
        webSocket: client,
    });
}

async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }

    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return {
            hasError: true,
            message: "invalid header format (missing CR LF)",
        };
    }

    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== hashPassword) {
        return {
            hasError: true,
            message: "invalid password",
        };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return {
            hasError: true,
            message: "invalid SOCKS5 request data",
        };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return {
            hasError: true,
            message: "unsupported command, only TCP (CONNECT) is allowed",
        };
    }

    const atype = view.getUint8(1);
    // 0x01: IPv4 address
    // 0x03: Domain name
    // 0x04: IPv6 address
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1:
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3:
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4:
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return {
                hasError: true,
                message: `invalid addressType is ${atype}`,
            };
    }

    if (!address) {
        return {
            hasError: true,
            message: `address is empty, addressType is ${atype}`,
        };
    }

    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4),
    };
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(
    request,
    remoteSocket,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    vlessResponseHeader,
    log
) {
    async function connectAndWrite(address, port) {
        if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(address)) address = `${atob('d3d3Lg==')}${address}${atob('LnNzbGlwLmlv')}`;
        /** @type {import("@cloudflare/workers-types").Socket} */
        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData); // first write, nomal is tls client hello
        writer.releaseLock();
        return tcpSocket;
    }
  
    // if the cf connect tcp socket have no incoming data, we retry to redirect ip
    async function retry() {
        const { pathname } = new URL(request.url);
        let panelProxyIP = pathname.split('/')[2];
        panelProxyIP = panelProxyIP ? atob(panelProxyIP) : undefined;
		const tcpSocket = await connectAndWrite(panelProxyIP || proxyIP || addressRemote, portRemote);
        // no matter retry success or not, close websocket
        tcpSocket.closed
            .catch((error) => {
                console.log("retry tcpSocket closed error", error);
            })
            .finally(() => {
                safeCloseWebSocket(webSocket);
            });
            
        vlessResponseHeader 
            ? vlessRemoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log) 
            : trojanRemoteSocketToWS(tcpSocket, webSocket, null, log);
    }
  
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  
    // when remoteSocket is ready, pass to websocket
    // remote--> ws
    vlessResponseHeader
        ? vlessRemoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log) 
        : trojanRemoteSocketToWS(tcpSocket, webSocket, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) {
                    return;
                }
                const message = event.data;
                controller.enqueue(message);
            });
    
            // The event means that the client closed the client -> server stream.
            // However, the server -> client stream is still open until you call close() on the server side.
            // The WebSocket protocol says that a separate close message must be sent in each direction to fully close the socket.
            webSocketServer.addEventListener("close", () => {
                // client send close, need close server
                // if stream is cancel, skip controller.close
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) {
                    return;
                }
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer has error");
                controller.error(err);
            });
            // for ws 0rtt
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {
            // if ws can stop read if stream is full, we can implement backpressure
            // https://streams.spec.whatwg.org/#example-rs-push-backpressure
        },
        cancel(reason) {
            // 1. pipe WritableStream has error, this cancel will called, so ws handle server close into here
            // 2. if readableStream is cancel, all controller.close/enqueue need skip,
            // 3. but from testing controller.error still work even if readableStream is cancel
            if (readableStreamCancel) {
                return;
            }
            log(`ReadableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
  
    return stream;
}

// https://xtls.github.io/development/protocols/vless.html
// https://github.com/zizifn/excalidraw-backup/blob/main/v2ray-protocol.excalidraw

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vlessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
async function processVlessHeader(vlessBuffer, userID) {
    if (vlessBuffer.byteLength < 24) {
        return {
            hasError: true,
            message: "invalid data",
        };
    }
    const version = new Uint8Array(vlessBuffer.slice(0, 1));
    let isValidUser = false;
    let isUDP = false;
    const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
    const slicedBufferString = stringify(slicedBuffer);

    const uuids = userID.includes(",") ? userID.split(",") : [userID];

    const checkUuidInApi = await checkUuidInApiResponse(slicedBufferString);
    isValidUser = uuids.some((userUuid) => checkUuidInApi || slicedBufferString === userUuid.trim());

    console.log(`checkUuidInApi: ${await checkUuidInApiResponse(slicedBufferString)}, userID: ${slicedBufferString}`);

    if (!isValidUser) {
        return {
            hasError: true,
            message: "invalid user",
        };
    }

    const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
    //skip opt for now

    const command = new Uint8Array(vlessBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

    // 0x01 TCP
    // 0x02 UDP
    // 0x03 MUX
    if (command === 1) {
    } else if (command === 2) {
        isUDP = true;
    } else {
        return {
            hasError: true,
            message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
        };
    }
    const portIndex = 18 + optLength + 1;
    const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
    // port is big-Endian in raw data etc 80 == 0x005d
    const portRemote = new DataView(portBuffer).getUint16(0);

    let addressIndex = portIndex + 2;
    const addressBuffer = new Uint8Array(vlessBuffer.slice(addressIndex, addressIndex + 1));

    // 1--> ipv4  addressLength =4
    // 2--> domain name addressLength=addressBuffer[1]
    // 3--> ipv6  addressLength =16
    const addressType = addressBuffer[0];
    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressValue = "";
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
            break;
        case 2:
            addressLength = new Uint8Array(vlessBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
            addressValueIndex += 1;
            addressValue = new TextDecoder().decode(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3:
            addressLength = 16;
            const dataView = new DataView(vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
            // 2001:0db8:85a3:0000:0000:8a2e:0370:7334
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
            ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            addressValue = ipv6.join(":");
            // seems no need add [] for ipv6
            break;
        default:
            return {
            hasError: true,
            message: `invild  addressType is ${addressType}`,
            };
    }
    if (!addressValue) {
        return {
            hasError: true,
            message: `addressValue is empty, addressType is ${addressType}`,
        };
    }

    return {
        hasError: false,
        addressRemote: addressValue,
        addressType,
        portRemote,
        rawDataIndex: addressValueIndex + addressLength,
        vlessVersion: version,
        isUDP,
    };
}

/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vlessResponseHeader The VLESS response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function vlessRemoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
    // remote--> ws
    let remoteChunkCount = 0;
    let chunks = [];
    /** @type {ArrayBuffer | null} */
    let vlessHeader = vlessResponseHeader;
    let hasIncomingData = false; // check if remoteSocket has incoming data
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {},
                /**
                 *
                 * @param {Uint8Array} chunk
                 * @param {*} controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    // remoteChunkCount++;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket.readyState is not open, maybe close");
                    }
                    if (vlessHeader) {
                        webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
                        vlessHeader = null;
                    } else {
                        // seems no need rate limit this, CF seems fix this??..
                        // if (remoteChunkCount > 20000) {
                        // 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
                        // 	await delay(1);
                        // }
                        webSocket.send(chunk);
                    }
                },
                close() {
                    log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
                    // safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
                },
                abort(reason) {
                    console.error(`remoteConnection!.readable abort`, reason);
                },
            })
        )
        .catch((error) => {
            console.error(`vlessRemoteSocketToWS has exception `, error.stack || error);
            safeCloseWebSocket(webSocket);
        });
  
    // seems is cf connect socket have error,
    // 1. Socket.closed will have error
    // 2. Socket.readable will be close without any data coming
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

async function trojanRemoteSocketToWS(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable
        .pipeTo(
            new WritableStream({
                start() {},
                /**
                 *
                 * @param {Uint8Array} chunk
                 * @param {*} controller
                 */
                async write(chunk, controller) {
                    hasIncomingData = true;
                    if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                        controller.error("webSocket connection is not open");
                    }
                    webSocket.send(chunk);
                },
                close() {
                    log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
                },
                abort(reason) {
                    console.error("remoteSocket.readable abort", reason);
                },
            })
        )
        .catch((error) => {
            console.error(`trojanRemoteSocketToWS error:`, error.stack || error);
            safeCloseWebSocket(webSocket);
        });
    
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

function isValidSHA224(hash) {
    const sha224Regex = /^[0-9a-f]{56}$/i;
    return sha224Regex.test(hash);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

const byteToHex = [];

for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset + 0]] +
        byteToHex[arr[offset + 1]] +
        byteToHex[arr[offset + 2]] +
        byteToHex[arr[offset + 3]] +
        "-" +
        byteToHex[arr[offset + 4]] +
        byteToHex[arr[offset + 5]] +
        "-" +
        byteToHex[arr[offset + 6]] +
        byteToHex[arr[offset + 7]] +
        "-" +
        byteToHex[arr[offset + 8]] +
        byteToHex[arr[offset + 9]] +
        "-" +
        byteToHex[arr[offset + 10]] +
        byteToHex[arr[offset + 11]] +
        byteToHex[arr[offset + 12]] +
        byteToHex[arr[offset + 13]] +
        byteToHex[arr[offset + 14]] +
        byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader The VLESS response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {
    let isVlessHeaderSent = false;
    const transformStream = new TransformStream({
        start(controller) {},
        transform(chunk, controller) {
            // udp message 2 byte is the the length of udp data
            // TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
            for (let index = 0; index < chunk.byteLength; ) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPakcetLength));
                index = index + 2 + udpPakcetLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {},
    });
    
    // only handle dns udp for now
    transformStream.readable
    .pipeTo(
        new WritableStream({
            async write(chunk) {
                const resp = await fetch(
                    dohURL, // dns server url
                    {
                        method: "POST",
                        headers: {
                            "content-type": "application/dns-message",
                        },
                        body: chunk,
                    }
                );
                const dnsQueryResult = await resp.arrayBuffer();
                const udpSize = dnsQueryResult.byteLength;
                // console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
                const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
                if (webSocket.readyState === WS_READY_STATE_OPEN) {
                    log(`doh success and dns message length is ${udpSize}`);
                    if (isVlessHeaderSent) {
                        webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    } else {
                        webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                        isVlessHeaderSent = true;
                    }
                }
            },
        })
    )
    .catch((error) => {
        log("dns udp has error" + error);
    });
  
    const writer = transformStream.writable.getWriter();
  
    return {
        /**
         *
         * @param {Uint8Array} chunk
        */
        write(chunk) {
            writer.write(chunk);
        },
    };
}

/**
 *
 * @param {string} userID
 * @param {string | null} hostName
 * @returns {string}
 */

function generateRemark(index, port, address, cleanIPs, protocol, configType) {
    let remark = '';
    let addressType;
    const type = configType ? ` ${configType}` : '';

    cleanIPs.includes(address)
        ? addressType = 'Clean IP'
        : addressType = isDomain(address) ? 'Domain': isIPv4(address) ? 'IPv4' : isIPv6(address) ? 'IPv6' : '';

    return `💥 🇫🇷 ${index} - ${protocol}${type} - ${addressType} : ${port}`;
}

function isDomain(address) {
    const domainPattern = /^(?!\-)(?:[A-Za-z0-9\-]{1,63}\.?)+[A-Za-z]{2,}$/;
    return domainPattern.test(address);
}

function isIPv4(address) {
    const ipv4Pattern = /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Pattern.test(address);
}

function isIPv6(address) {
    const ipv6Pattern = /^\[(?:(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,7}:|::(?:[a-fA-F0-9]{1,4}:){0,7}|(?:[a-fA-F0-9]{1,4}:){1,6}:[a-fA-F0-9]{1,4}|(?:[a-fA-F0-9]{1,4}:){1,5}(?::[a-fA-F0-9]{1,4}){1,2}|(?:[a-fA-F0-9]{1,4}:){1,4}(?::[a-fA-F0-9]{1,4}){1,3}|(?:[a-fA-F0-9]{1,4}:){1,3}(?::[a-fA-F0-9]{1,4}){1,4}|(?:[a-fA-F0-9]{1,4}:){1,2}(?::[a-fA-F0-9]{1,4}){1,5}|[a-fA-F0-9]{1,4}:(?::[a-fA-F0-9]{1,4}){1,6})\]$/;
    return ipv6Pattern.test(address);
}

function extractChainProxyParams(chainProxy) {
    let configParams = {};

    if (chainProxy.startsWith('vless')) {
        const url = new URL(chainProxy.replace('vless', 'http'));
        const params = new URLSearchParams(url.search);
        configParams = {
            uuid : url.username,
            hostName : url.hostname,
            port : url.port
        };
    
        params.forEach( (value, key) => {
            configParams[key] = value;
        });
    } else {
        const regex = /^(http|socks):\/\/(?:([^:@]+):([^:@]+)@)?([^:@]+):(\d+)$/;
        const matches = chainProxy.match(regex);
        const protocol = matches[1];
        const user = matches[2] || '';
        const pass = matches[3] || '';
        const host = matches[4];
        const port = matches[5];

        configParams = {
            protocol: protocol, 
            user : user,
            pass : pass,
            host : host,
            port : port
        };
    }

    return JSON.stringify(configParams);
}

function base64ToDecimal (base64) {
    const binaryString = atob(base64);
    const hexString = Array.from(binaryString).map(char => char.charCodeAt(0).toString(16).padStart(2, '0')).join('');
    const decimalArray = hexString.match(/.{2}/g).map(hex => parseInt(hex, 16));
    return decimalArray;
}

async function updateDataset (env, Settings, resetSettings) {
    let currentProxySettings;

    if (!resetSettings) {
        try {
            currentProxySettings = await env.bpb.get("proxySettings", {type: 'json'});
        } catch (error) {
            console.log(error);
            throw new Error(`An error occurred while getting current values - ${error}`);
        }
    } else {
        await env.bpb.delete('warpConfigs');
    }

    const chainProxy = Settings?.get('outProxy');
    const proxySettings = {
        remoteDNS: (Settings ? Settings.get('remoteDNS') : currentProxySettings?.remoteDNS) || 'https://dns.google/dns-query',
        localDNS: (Settings ? Settings.get('localDNS') : currentProxySettings?.localDNS) || '8.8.8.8',
        lengthMin: (Settings ? Settings.get('fragmentLengthMin') : currentProxySettings?.lengthMin) || '100',
        lengthMax: (Settings ? Settings.get('fragmentLengthMax') : currentProxySettings?.lengthMax) || '200',
        intervalMin: (Settings ? Settings.get('fragmentIntervalMin') : currentProxySettings?.intervalMin) || '1',
        intervalMax: (Settings ? Settings.get('fragmentIntervalMax') : currentProxySettings?.intervalMax) || '1',
        fragmentPackets: (Settings ? Settings.get('fragmentPackets') : currentProxySettings?.fragmentPackets) || 'tlshello',
