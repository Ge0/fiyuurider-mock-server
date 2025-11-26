// redirect-webview-loadurl.js  (WebView OAuth + RN API)
'use strict';

const WEBVIEW_FROM = "https://oauth2.riders.fiyuu.com.tr";
const WEBVIEW_TO   = "http://192.168.1.37:3000";

const RN_FROM = "https://svc.riders.fiyuu.com.tr/fiyuu/rider";
const RN_TO   = "http://192.168.1.37:3000/fiyuu/rider";

const FROM_SVC = "https://svc.riders.fiyuu.com.tr/fiyuu/rider";
const TO_SVC   = "http://192.168.1.37:3000";   // <-- ton backend

function rewriteSvc(u) {
  if (!u) return u;
  if (u.startsWith(FROM_SVC)) {
    const nu = TO_SVC + u.slice(FROM_SVC.length);
    console.log(`[REDIRECT/RN] ${u} -> ${nu}`);
    return nu;
  } else if (u.startsWith(WEBVIEW_FROM)) {
    const nu = TO_SVC + u.slice(WEBVIEW_FROM.length);
    console.log(`[REDIRECT/RN] ${u} -> ${nu}`);
    return nu;
  }
  return u;
}

function rewriteWebView(u) {
  if (!u) return u;
  if (u.startsWith(WEBVIEW_FROM)) {
    const nu = WEBVIEW_TO + u.slice(WEBVIEW_FROM.length);
    console.log(`[REDIRECT/WebView] ${u} -> ${nu}`);
    return nu;
  }
  return u;
}

function rewriteRN(u) {
  if (!u) return u;
  if (u.startsWith(RN_FROM)) {
    const nu = RN_TO + u.slice(RN_FROM.length);
    console.log(`[REDIRECT/RN] ${u} -> ${nu}`);
    return nu;
  }
  return u;
}

function looksLikeUrl(s) {
  return s.startsWith("http://") || s.startsWith("https://");
}

Java.perform(() => {
  /* ===================== WebView hooks (OAuth only) ===================== */
  const WebView = Java.use('android.webkit.WebView');

  // loadUrl(String)
  const loadUrlStr = WebView.loadUrl.overload('java.lang.String');
  loadUrlStr.implementation = function (url) {
    const nu = rewriteWebView(url);
    return loadUrlStr.call(this, nu);
  };

  // loadUrl(String, Map)
  const loadUrlMap = WebView.loadUrl.overload('java.lang.String', 'java.util.Map');
  loadUrlMap.implementation = function (url, headers) {
    const nu = rewriteWebView(url);
    return loadUrlMap.call(this, nu, headers);
  };

  console.log('[*] WebView.loadUrl redirect hooks installed (OAuth only)');

  
  const NM = Java.use('com.facebook.react.modules.network.NetworkingModule');

  // sendRequestInternal(String method, String url, int requestId, ReadableArray headers, ReadableMap data, ...)
  const sri = NM.sendRequestInternal.overload(
    'java.lang.String',
    'java.lang.String',
    'int',
    'com.facebook.react.bridge.ReadableArray',
    'com.facebook.react.bridge.ReadableMap',
    'java.lang.String',
    'boolean',
    'int',
    'boolean'
  );

  sri.implementation = function (method, url, requestId, headers, data, responseType, useIncremental, timeout, withCredentials) {
    
    /*
    console.log(method);
    console.log(url);
    */
    const nu = rewriteSvc(url);
    console.log(nu);
    return sri.call(this, method, nu, requestId, headers, data, responseType, useIncremental, timeout, withCredentials);
  };

  console.log('[*] NetworkingModule.sendRequestInternal redirect hook installed');
  
});
