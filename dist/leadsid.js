(function( window, undefined ) {

    var LeadsID = function (config) {
        if (!(this instanceof LeadsID)) {
            return new LeadsID(config);
        }

        var leads = this;
        var adapter;
        var refreshQueue = [];

        var loginIframe = {
            enable: true,
            callbackMap: [],
            interval: 5
        };

        leads.init = function (initOptions) {
            leads.authenticated = false;

            if (window.Cordova) {
                adapter = loadAdapter('cordova');
            } else {
                adapter = loadAdapter();
            }

            if (initOptions) {
                if (typeof initOptions.checkLoginIframe !== 'undefined') {
                    loginIframe.enable = initOptions.checkLoginIframe;
                }

                if (initOptions.checkLoginIframeInterval) {
                    loginIframe.interval = initOptions.checkLoginIframeInterval;
                }

                if (initOptions.onLoad === 'login-required') {
                    leads.loginRequired = true;
                }

                if (initOptions.responseMode) {
                    if (initOptions.responseMode === 'query' || initOptions.responseMode === 'fragment') {
                        leads.responseMode = initOptions.responseMode;
                    } else {
                        throw 'Invalid value for responseMode';
                    }
                }

                if (initOptions.flow) {
                    switch (initOptions.flow) {
                        case 'standard':
                            leads.responseType = 'code';
                            break;
                        case 'implicit':
                            leads.responseType = 'id_token token';
                            break;
                        case 'hybrid':
                            leads.responseType = 'code id_token token';
                            break;
                        default:
                            throw 'Invalid value for flow';
                    }
                    leads.flow = initOptions.flow;
                }
            }

            if (!leads.responseMode) {
                leads.responseMode = 'fragment';
            }
            if (!leads.responseType) {
                leads.responseType = 'code';
                leads.flow = 'standard';
            }

            var promise = createPromise();

            var initPromise = createPromise();
            initPromise.promise.success(function() {
                leads.onReady && leads.onReady(leads.authenticated);
                promise.setSuccess(leads.authenticated);
            }).error(function() {
                promise.setError();
            });

            var configPromise = loadConfig(config);

            function onLoad() {
                var doLogin = function(prompt) {
                    if (!prompt) {
                        options.prompt = 'none';
                    }
                    leads.login(options).success(function () {
                        initPromise.setSuccess();
                    }).error(function () {
                        initPromise.setError();
                    });
                }

                var options = {};
                switch (initOptions.onLoad) {
                    case 'check-sso':
                        if (loginIframe.enable) {
                            setupCheckLoginIframe().success(function() {
                                checkLoginIframe().success(function () {
                                    doLogin(false);
                                }).error(function () {
                                    initPromise.setSuccess();
                                });
                            });
                        } else {
                            doLogin(false);
                        }
                        break;
                    case 'login-required':
                        doLogin(true);
                        break;
                    default:
                        throw 'Invalid value for onLoad';
                }
            }

            function processInit() {
                var callback = parseCallback(window.location.href);

                if (callback) {
                    setupCheckLoginIframe();
                    window.history.replaceState({}, null, callback.newUrl);
                    processCallback(callback, initPromise);
                    return;
                } else if (initOptions) {
                    if (initOptions.token || initOptions.refreshToken) {
                        setToken(initOptions.token, initOptions.refreshToken, initOptions.idToken, false);

                        if (loginIframe.enable) {
                            setupCheckLoginIframe().success(function() {
                                checkLoginIframe().success(function () {
                                    initPromise.setSuccess();
                                }).error(function () {
                                    if (initOptions.onLoad) {
                                        onLoad();
                                    }
                                });
                            });
                        } else {
                            initPromise.setSuccess();
                        }
                    } else if (initOptions.onLoad) {
                        onLoad();
                    }
                } else {
                    initPromise.setSuccess();
                }
            }

            configPromise.success(processInit);
            configPromise.error(function() {
                promise.setError();
            });

            return promise.promise;
        }

        leads.login = function (options) {
            return adapter.login(options);
        }

        leads.createLoginUrl = function(options) {
            var state = createUUID();
            var nonce = createUUID();

            var redirectUri = adapter.redirectUri(options);
            if (options && options.prompt) {
                redirectUri += (redirectUri.indexOf('?') == -1 ? '?' : '&') + 'prompt=' + options.prompt;
            }

            sessionStorage.oauthState = JSON.stringify({ state: state, nonce: nonce, redirectUri: encodeURIComponent(redirectUri) });

            var action = 'auth';
            if (options && options.action == 'register') {
                action = 'registrations';
            }

            var url = getRealmUrl()
                + '/protocol/openid-connect/' + action
                + '?client_id=' + encodeURIComponent(leads.clientId)
                + '&redirect_uri=' + encodeURIComponent(redirectUri)
                + '&state=' + encodeURIComponent(state)
                + '&nonce=' + encodeURIComponent(nonce)
                + '&response_mode=' + encodeURIComponent(leads.responseMode)
                + '&response_type=' + encodeURIComponent(leads.responseType);

            if (options && options.prompt) {
                url += '&prompt=' + encodeURIComponent(options.prompt);
            }

            if (options && options.loginHint) {
                url += '&login_hint=' + encodeURIComponent(options.loginHint);
            }

            if (options && options.idpHint) {
                url += '&kc_idp_hint=' + encodeURIComponent(options.idpHint);
            }

            if (options && options.scope) {
                url += '&scope=' + encodeURIComponent(options.scope);
            }

            if (options && options.locale) {
                url += '&ui_locales=' + encodeURIComponent(options.locale);
            }

            return url;
        }

        leads.logout = function(options) {
            return adapter.logout(options);
        }

        leads.createLogoutUrl = function(options) {
            var url = getRealmUrl()
                + '/protocol/openid-connect/logout'
                + '?redirect_uri=' + encodeURIComponent(adapter.redirectUri(options));

            return url;
        }

        leads.register = function (options) {
            return adapter.register(options);
        }

        leads.createRegisterUrl = function(options) {
            if (!options) {
                options = {};
            }
            options.action = 'register';
            return leads.createLoginUrl(options);
        }

        leads.createAccountUrl = function(options) {
            var url = getRealmUrl()
                + '/account'
                + '?referrer=' + encodeURIComponent(leads.clientId)
                + '&referrer_uri=' + encodeURIComponent(adapter.redirectUri(options));

            return url;
        }

        leads.accountManagement = function() {
            return adapter.accountManagement();
        }

        leads.hasRealmRole = function (role) {
            var access = leads.realmAccess;
            return !!access && access.roles.indexOf(role) >= 0;
        }

        leads.hasResourceRole = function(role, resource) {
            if (!leads.resourceAccess) {
                return false;
            }

            var access = leads.resourceAccess[resource || leads.clientId];
            return !!access && access.roles.indexOf(role) >= 0;
        }

        leads.loadUserProfile = function() {
            var url = getRealmUrl() + '/account';
            var req = new XMLHttpRequest();
            req.open('GET', url, true);
            req.setRequestHeader('Accept', 'application/json');
            req.setRequestHeader('Authorization', 'bearer ' + leads.token);

            var promise = createPromise();

            req.onreadystatechange = function () {
                if (req.readyState == 4) {
                    if (req.status == 200) {
                        leads.profile = JSON.parse(req.responseText);
                        promise.setSuccess(leads.profile);
                    } else {
                        promise.setError();
                    }
                }
            }

            req.send();

            return promise.promise;
        }

        leads.loadUserInfo = function() {
            var url = getRealmUrl() + '/protocol/openid-connect/userinfo';
            var req = new XMLHttpRequest();
            req.open('GET', url, true);
            req.setRequestHeader('Accept', 'application/json');
            req.setRequestHeader('Authorization', 'bearer ' + leads.token);

            var promise = createPromise();

            req.onreadystatechange = function () {
                if (req.readyState == 4) {
                    if (req.status == 200) {
                        leads.userInfo = JSON.parse(req.responseText);
                        promise.setSuccess(leads.userInfo);
                    } else {
                        promise.setError();
                    }
                }
            }

            req.send();

            return promise.promise;
        }

        leads.isTokenExpired = function(minValidity) {
            if (!leads.tokenParsed || (!leads.refreshToken && leads.flow != 'implicit' )) {
                throw 'Not authenticated';
            }

            var expiresIn = leads.tokenParsed['exp'] - (new Date().getTime() / 1000) + leads.timeSkew;
            if (minValidity) {
                expiresIn -= minValidity;
            }

            return expiresIn < 0;
        }

        leads.updateToken = function(minValidity) {
            var promise = createPromise();

            if (!leads.tokenParsed || !leads.refreshToken) {
                promise.setError();
                return promise.promise;
            }

            minValidity = minValidity || 5;

            var exec = function() {
                if (!leads.isTokenExpired(minValidity)) {
                    promise.setSuccess(false);
                } else {
                    var params = 'grant_type=refresh_token&' + 'refresh_token=' + leads.refreshToken;
                    var url = getRealmUrl() + '/protocol/openid-connect/token';

                    refreshQueue.push(promise);

                    if (refreshQueue.length == 1) {
                        var req = new XMLHttpRequest();
                        req.open('POST', url, true);
                        req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                        if (leads.clientId && leads.clientSecret) {
                            req.setRequestHeader('Authorization', 'Basic ' + btoa(leads.clientId + ':' + leads.clientSecret));
                        } else {
                            params += '&client_id=' + encodeURIComponent(leads.clientId);
                        }

                        var timeLocal = new Date().getTime();

                        req.onreadystatechange = function () {
                            if (req.readyState == 4) {
                                if (req.status == 200) {
                                    timeLocal = (timeLocal + new Date().getTime()) / 2;

                                    var tokenResponse = JSON.parse(req.responseText);
                                    setToken(tokenResponse['access_token'], tokenResponse['refresh_token'], tokenResponse['id_token'], true);

                                    leads.timeSkew = Math.floor(timeLocal / 1000) - leads.tokenParsed.iat;

                                    leads.onAuthRefreshSuccess && leads.onAuthRefreshSuccess();
                                    for (var p = refreshQueue.pop(); p != null; p = refreshQueue.pop()) {
                                        p.setSuccess(true);
                                    }
                                } else {
                                    leads.onAuthRefreshError && leads.onAuthRefreshError();
                                    for (var p = refreshQueue.pop(); p != null; p = refreshQueue.pop()) {
                                        p.setError(true);
                                    }
                                }
                            }
                        };

                        req.send(params);
                    }
                }
            }

            if (loginIframe.enable) {
                var iframePromise = checkLoginIframe();
                iframePromise.success(function() {
                    exec();
                }).error(function() {
                    promise.setError();
                });
            } else {
                exec();
            }

            return promise.promise;
        }

        leads.clearToken = function() {
            if (leads.token) {
                setToken(null, null, null, true);
                leads.onAuthLogout && leads.onAuthLogout();
                if (leads.loginRequired) {
                    leads.login();
                }
            }
        }

        function getRealmUrl() {
            if (leads.authServerUrl.charAt(leads.authServerUrl.length - 1) == '/') {
                return leads.authServerUrl + 'realms/' + encodeURIComponent(leads.realm);
            } else {
                return leads.authServerUrl + '/realms/' + encodeURIComponent(leads.realm);
            }
        }

        function getOrigin() {
            if (!window.location.origin) {
                return window.location.protocol + "//" + window.location.hostname + (window.location.port ? ':' + window.location.port: '');
            } else {
                return window.location.origin;
            }
        }

        function processCallback(oauth, promise) {
            var code = oauth.code;
            var error = oauth.error;
            var prompt = oauth.prompt;

            var timeLocal = new Date().getTime();

            if (error) {
                if (prompt != 'none') {
                    leads.onAuthError && leads.onAuthError();
                    promise && promise.setError();
                } else {
                    promise && promise.setSuccess();
                }
                return;
            } else if ((leads.flow != 'standard') && (oauth.access_token || oauth.id_token)) {
                authSuccess(oauth.access_token, null, oauth.id_token, true);
            }

            if ((leads.flow != 'implicit') && code) {
                var params = 'code=' + code + '&grant_type=authorization_code';
                var url = getRealmUrl() + '/protocol/openid-connect/token';

                var req = new XMLHttpRequest();
                req.open('POST', url, true);
                req.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');

                if (leads.clientId && leads.clientSecret) {
                    req.setRequestHeader('Authorization', 'Basic ' + btoa(leads.clientId + ':' + leads.clientSecret));
                } else {
                    params += '&client_id=' + encodeURIComponent(leads.clientId);
                }

                params += '&redirect_uri=' + oauth.redirectUri;

                req.withCredentials = true;

                req.onreadystatechange = function() {
                    if (req.readyState == 4) {
                        if (req.status == 200) {

                            var tokenResponse = JSON.parse(req.responseText);
                            authSuccess(tokenResponse['access_token'], tokenResponse['refresh_token'], tokenResponse['id_token'], leads.flow === 'standard');
                        } else {
                            leads.onAuthError && leads.onAuthError();
                            promise && promise.setError();
                        }
                    }
                };

                req.send(params);
            }

            function authSuccess(accessToken, refreshToken, idToken, fulfillPromise) {
                timeLocal = (timeLocal + new Date().getTime()) / 2;

                setToken(accessToken, refreshToken, idToken, true);

                if ((leads.tokenParsed && leads.tokenParsed.nonce != oauth.storedNonce) ||
                    (leads.refreshTokenParsed && leads.refreshTokenParsed.nonce != oauth.storedNonce) ||
                    (leads.idTokenParsed && leads.idTokenParsed.nonce != oauth.storedNonce)) {

                    console.log('invalid nonce!');
                    leads.clearToken();
                    promise && promise.setError();
                } else {
                    leads.timeSkew = Math.floor(timeLocal / 1000) - leads.tokenParsed.iat;

                    if (fulfillPromise) {
                        leads.onAuthSuccess && leads.onAuthSuccess();
                        promise && promise.setSuccess();
                    }
                }
            }

        }

        function loadConfig(url) {
            var promise = createPromise();
            var configUrl;

            if (!config) {
                configUrl = 'leadsid.json';
            } else if (typeof config === 'string') {
                configUrl = config;
            }

            if (configUrl) {
                var req = new XMLHttpRequest();
                req.open('GET', configUrl, true);
                req.setRequestHeader('Accept', 'application/json');

                req.onreadystatechange = function () {
                    if (req.readyState == 4) {
                        if (req.status == 200) {
                            var config = JSON.parse(req.responseText);

                            leads.authServerUrl = config['auth-server-url'];
                            leads.realm = config['realm'];
                            leads.clientId = config['resource'];
                            leads.clientSecret = (config['credentials'] || {})['secret'];

                            promise.setSuccess();
                        } else {
                            promise.setError();
                        }
                    }
                };

                req.send();
            } else {
                if (!config['url']) {
                    var scripts = document.getElementsByTagName('script');
                    for (var i = 0; i < scripts.length; i++) {
                        if (scripts[i].src.match(/.*leadsid\.js/)) {
                            config.url = scripts[i].src.substr(0, scripts[i].src.indexOf('/js/leadsid.js'));
                            break;
                        }
                    }
                }

                if (!config.realm) {
                    throw 'realm missing';
                }

                if (!config.clientId) {
                    throw 'clientId missing';
                }

                leads.authServerUrl = config.url;
                leads.realm = config.realm;
                leads.clientId = config.clientId;
                leads.clientSecret = (config.credentials || {}).secret;

                promise.setSuccess();
            }

            return promise.promise;
        }

        function setToken(token, refreshToken, idToken, useTokenTime) {
            if (leads.tokenTimeoutHandle) {
                clearTimeout(leads.tokenTimeoutHandle);
                leads.tokenTimeoutHandle = null;
            }

            if (token) {
                leads.token = token;
                leads.tokenParsed = decodeToken(token);
                var sessionId = leads.realm + '/' + leads.tokenParsed.sub;
                if (leads.tokenParsed.session_state) {
                    sessionId = sessionId + '/' + leads.tokenParsed.session_state;
                }
                leads.sessionId = sessionId;
                leads.authenticated = true;
                leads.subject = leads.tokenParsed.sub;
                leads.realmAccess = leads.tokenParsed.realm_access;
                leads.resourceAccess = leads.tokenParsed.resource_access;

                if (leads.onTokenExpired) {
                    var start = useTokenTime ? leads.tokenParsed.iat : (new Date().getTime() / 1000);
                    var expiresIn = leads.tokenParsed.exp - start;
                    leads.tokenTimeoutHandle = setTimeout(leads.onTokenExpired, expiresIn * 1000);
                }

            } else {
                delete leads.token;
                delete leads.tokenParsed;
                delete leads.subject;
                delete leads.realmAccess;
                delete leads.resourceAccess;

                leads.authenticated = false;
            }

            if (refreshToken) {
                leads.refreshToken = refreshToken;
                leads.refreshTokenParsed = decodeToken(refreshToken);
            } else {
                delete leads.refreshToken;
                delete leads.refreshTokenParsed;
            }

            if (idToken) {
                leads.idToken = idToken;
                leads.idTokenParsed = decodeToken(idToken);
            } else {
                delete leads.idToken;
                delete leads.idTokenParsed;
            }
        }

        function decodeToken(str) {
            str = str.split('.')[1];

            str = str.replace('/-/g', '+');
            str = str.replace('/_/g', '/');
            switch (str.length % 4)
            {
                case 0:
                    break;
                case 2:
                    str += '==';
                    break;
                case 3:
                    str += '=';
                    break;
                default:
                    throw 'Invalid token';
            }

            str = (str + '===').slice(0, str.length + (str.length % 4));
            str = str.replace(/-/g, '+').replace(/_/g, '/');

            str = decodeURIComponent(escape(atob(str)));

            str = JSON.parse(str);
            return str;
        }

        function createUUID() {
            var s = [];
            var hexDigits = '0123456789abcdef';
            for (var i = 0; i < 36; i++) {
                s[i] = hexDigits.substr(Math.floor(Math.random() * 0x10), 1);
            }
            s[14] = '4';
            s[19] = hexDigits.substr((s[19] & 0x3) | 0x8, 1);
            s[8] = s[13] = s[18] = s[23] = '-';
            var uuid = s.join('');
            return uuid;
        }

        leads.callback_id = 0;

        function createCallbackId() {
            var id = '<id: ' + (leads.callback_id++) + (Math.random()) + '>';
            return id;

        }

        function parseCallback(url) {
            var oauth = new CallbackParser(url, leads.responseMode).parseUri();

            var sessionState = sessionStorage.oauthState && JSON.parse(sessionStorage.oauthState);

            if (sessionState && (oauth.code || oauth.error || oauth.access_token || oauth.id_token) && oauth.state && oauth.state == sessionState.state) {
                delete sessionStorage.oauthState;

                oauth.redirectUri = sessionState.redirectUri;
                oauth.storedNonce = sessionState.nonce;

                if (oauth.fragment) {
                    oauth.newUrl += '#' + oauth.fragment;
                }

                return oauth;
            }
        }

        function createPromise() {
            var p = {
                setSuccess: function(result) {
                    p.success = true;
                    p.result = result;
                    if (p.successCallback) {
                        p.successCallback(result);
                    }
                },

                setError: function(result) {
                    p.error = true;
                    p.result = result;
                    if (p.errorCallback) {
                        p.errorCallback(result);
                    }
                },

                promise: {
                    success: function(callback) {
                        if (p.success) {
                            callback(p.result);
                        } else if (!p.error) {
                            p.successCallback = callback;
                        }
                        return p.promise;
                    },
                    error: function(callback) {
                        if (p.error) {
                            callback(p.result);
                        } else if (!p.success) {
                            p.errorCallback = callback;
                        }
                        return p.promise;
                    }
                }
            }
            return p;
        }

        function setupCheckLoginIframe() {
            var promise = createPromise();

            if (!loginIframe.enable) {
                promise.setSuccess();
                return promise.promise;
            }

            if (loginIframe.iframe) {
                promise.setSuccess();
                return promise.promise;
            }

            var iframe = document.createElement('iframe');
            loginIframe.iframe = iframe;

            iframe.onload = function() {
                var realmUrl = getRealmUrl();
                if (realmUrl.charAt(0) === '/') {
                    loginIframe.iframeOrigin = getOrigin();
                } else {
                    loginIframe.iframeOrigin = realmUrl.substring(0, realmUrl.indexOf('/', 8));
                }
                promise.setSuccess();

                setTimeout(check, loginIframe.interval * 1000);
            }

            var src = getRealmUrl() + '/protocol/openid-connect/login-status-iframe.html?client_id=' + encodeURIComponent(leads.clientId) + '&origin=' + getOrigin();
            iframe.setAttribute('src', src );
            iframe.style.display = 'none';
            document.body.appendChild(iframe);

            var messageCallback = function(event) {
                if (event.origin !== loginIframe.iframeOrigin) {
                    return;
                }
                var data = JSON.parse(event.data);
                var promise = loginIframe.callbackMap[data.callbackId];
                delete loginIframe.callbackMap[data.callbackId];

                if ((!leads.sessionId || leads.sessionId == data.session) && data.loggedIn) {
                    promise.setSuccess();
                } else {
                    leads.clearToken();
                    promise.setError();
                }
            };
            window.addEventListener('message', messageCallback, false);

            var check = function() {
                checkLoginIframe();
                if (leads.token) {
                    setTimeout(check, loginIframe.interval * 1000);
                }
            };

            return promise.promise;
        }

        function checkLoginIframe() {
            var promise = createPromise();

            if (loginIframe.iframe && loginIframe.iframeOrigin) {
                var msg = {};
                msg.callbackId = createCallbackId();
                loginIframe.callbackMap[msg.callbackId] = promise;
                var origin = loginIframe.iframeOrigin;
                loginIframe.iframe.contentWindow.postMessage(JSON.stringify(msg), origin);
            } else {
                promise.setSuccess();
            }

            return promise.promise;
        }

        function loadAdapter(type) {
            if (!type || type == 'default') {
                return {
                    login: function(options) {
                        window.location.href = leads.createLoginUrl(options);
                        return createPromise().promise;
                    },

                    logout: function(options) {
                        window.location.href = leads.createLogoutUrl(options);
                        return createPromise().promise;
                    },

                    register: function(options) {
                        window.location.href = leads.createRegisterUrl(options);
                        return createPromise().promise;
                    },

                    accountManagement : function() {
                        window.location.href = leads.createAccountUrl();
                        return createPromise().promise;
                    },

                    redirectUri: function(options) {
                        if (options && options.redirectUri) {
                            return options.redirectUri;
                        } else if (leads.redirectUri) {
                            return leads.redirectUri;
                        } else {
                            var redirectUri = location.href;
                            if (location.hash) {
                                redirectUri = redirectUri.substring(0, location.href.indexOf('#'));
                                redirectUri += (redirectUri.indexOf('?') == -1 ? '?' : '&') + 'redirect_fragment=' + encodeURIComponent(location.hash.substring(1));
                            }
                            return redirectUri;
                        }
                    }
                };
            }

            if (type == 'cordova') {
                loginIframe.enable = false;

                return {
                    login: function(options) {
                        var promise = createPromise();

                        var o = 'location=no';
                        if (options && options.prompt == 'none') {
                            o += ',hidden=yes';
                        }

                        var loginUrl = leads.createLoginUrl(options);
                        var ref = window.open(loginUrl, '_blank', o);

                        var callback;
                        var error;

                        ref.addEventListener('loadstart', function(event) {
                            if (event.url.indexOf('http://localhost') == 0) {
                                callback = parseCallback(event.url);
                                ref.close();
                            }
                        });

                        ref.addEventListener('loaderror', function(event) {
                            if (event.url.indexOf('http://localhost') != 0) {
                                error = true;
                                ref.close();
                            }
                        });

                        ref.addEventListener('exit', function(event) {
                            if (error || !callback) {
                                promise.setError();
                            } else {
                                processCallback(callback, promise);
                            }
                        });

                        return promise.promise;
                    },

                    logout: function(options) {
                        var promise = createPromise();

                        var logoutUrl = leads.createLogoutUrl(options);
                        var ref = window.open(logoutUrl, '_blank', 'location=no,hidden=yes');

                        var error;

                        ref.addEventListener('loadstart', function(event) {
                            if (event.url.indexOf('http://localhost') == 0) {
                                ref.close();
                            }
                        });

                        ref.addEventListener('loaderror', function(event) {
                            if (event.url.indexOf('http://localhost') != 0) {
                                error = true;
                                ref.close();
                            }
                        });

                        ref.addEventListener('exit', function(event) {
                            if (error) {
                                promise.setError();
                            } else {
                                leads.clearToken();
                                promise.setSuccess();
                            }
                        });

                        return promise.promise;
                    },

                    register : function() {
                        var registerUrl = leads.createRegisterUrl();
                        var ref = window.open(registerUrl, '_blank', 'location=no');
                        ref.addEventListener('loadstart', function(event) {
                            if (event.url.indexOf('http://localhost') == 0) {
                                ref.close();
                            }
                        });
                    },

                    accountManagement : function() {
                        var accountUrl = leads.createAccountUrl();
                        var ref = window.open(accountUrl, '_blank', 'location=no');
                        ref.addEventListener('loadstart', function(event) {
                            if (event.url.indexOf('http://localhost') == 0) {
                                ref.close();
                            }
                        });
                    },

                    redirectUri: function(options) {
                        return 'http://localhost';
                    }
                }
            }

            throw 'invalid adapter type: ' + type;
        }


        var CallbackParser = function(uriToParse, responseMode) {
            if (!(this instanceof CallbackParser)) {
                return new CallbackParser(uriToParse, responseMode);
            }
            var parser = this;

            var initialParse = function() {
                var baseUri = null;
                var queryString = null;
                var fragmentString = null;

                var questionMarkIndex = uriToParse.indexOf("?");
                var fragmentIndex = uriToParse.indexOf("#", questionMarkIndex + 1);
                if (questionMarkIndex == -1 && fragmentIndex == -1) {
                    baseUri = uriToParse;
                } else if (questionMarkIndex != -1) {
                    baseUri = uriToParse.substring(0, questionMarkIndex);
                    queryString = uriToParse.substring(questionMarkIndex + 1);
                    if (fragmentIndex != -1) {
                        fragmentIndex = queryString.indexOf("#");
                        fragmentString = queryString.substring(fragmentIndex + 1);
                        queryString = queryString.substring(0, fragmentIndex);
                    }
                } else {
                    baseUri = uriToParse.substring(0, fragmentIndex);
                    fragmentString = uriToParse.substring(fragmentIndex + 1);
                }

                return { baseUri: baseUri, queryString: queryString, fragmentString: fragmentString };
            }

            var parseParams = function(paramString) {
                var result = {};
                var params = paramString.split('&');
                for (var i = 0; i < params.length; i++) {
                    var p = params[i].split('=');
                    var paramName = decodeURIComponent(p[0]);
                    var paramValue = decodeURIComponent(p[1]);
                    result[paramName] = paramValue;
                }
                return result;
            }

            var handleQueryParam = function(paramName, paramValue, oauth) {
                var supportedOAuthParams = [ 'code', 'error', 'state' ];

                for (var i = 0 ; i< supportedOAuthParams.length ; i++) {
                    if (paramName === supportedOAuthParams[i]) {
                        oauth[paramName] = paramValue;
                        return true;
                    }
                }
                return false;
            }


            parser.parseUri = function() {
                var parsedUri = initialParse();

                var queryParams = {};
                if (parsedUri.queryString) {
                    queryParams = parseParams(parsedUri.queryString);
                }

                var oauth = { newUrl: parsedUri.baseUri };
                for (var param in queryParams) {
                    switch (param) {
                        case 'redirect_fragment':
                            oauth.fragment = queryParams[param];
                            break;
                        case 'prompt':
                            oauth.prompt = queryParams[param];
                            break;
                        default:
                            if (responseMode != 'query' || !handleQueryParam(param, queryParams[param], oauth)) {
                                oauth.newUrl += (oauth.newUrl.indexOf('?') == -1 ? '?' : '&') + param + '=' + queryParams[param];
                            }
                            break;
                    }
                }

                if (responseMode === 'fragment') {
                    var fragmentParams = {};
                    if (parsedUri.fragmentString) {
                        fragmentParams = parseParams(parsedUri.fragmentString);
                    }
                    for (var param in fragmentParams) {
                        oauth[param] = fragmentParams[param];
                    }
                }

                return oauth;
            }
        }

    }

    if ( typeof module === "object" && module && typeof module.exports === "object" ) {
        module.exports = LeadsID;
    } else {
        window.LeadsID = LeadsID;

        if ( typeof define === "function" && define.amd ) {
            define( "leadsid", [], function () { return LeadsID; } );
        }
    }
})( window );
