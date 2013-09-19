/* SimpleOAuth - Simply builds OAuth 1.0 headers
*
* Copyright (c) 2013, Ben Olson (github.com/bseth99/simple-oauth-js)
*
* Adapted from Ruby Gem simple_oauth:
*   https://github.com/laserlemon/simple_oauth
*
* and OAuthSimple:
*   http://unitedHeroes.net/OAuthSimple
*
* Usage is essentially the same and should match the Ruby versions output
* for server-side processing.
*
*
* This basic usage will yield a string suitable for setting on the
* Authorization header in an AJAX request.  It is not library specific
* nor does it assume which header you will use it with:
*
*   var options = {
*      consumer_key: 'R1Y3QW1L15uw8X0t5ddJbQ',
*      consumer_secret: '7xKJvmTCKm97WBQQllji9Oz8DRQHJoN1svhiY8vo'
*   };
*
*   var header = new SimpleOAuth.Header('get', 'http://example.org/resource', null, options);
*   var authorization = header.build();
*
* See github.com/bseth99/simple-oauth for more usage examples and notes
* Also check the test cases and samples for jQuery/Backbone integration cases
*
* Only support HMAC-SHA1 signing
*
* Other sources noted throughout.
*
* Dependancies:
*     underscore.js >= 1.4.3 (http://underscorejs.org)
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*     * Redistributions of source code must retain the above copyright
*       notice, this list of conditions and the following disclaimer.
*     * Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*     * Neither the name of the unitedHeroes.net nor the
*       names of its contributors may be used to endorse or promote products
*       derived from this software without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY UNITEDHEROES.NET ''AS IS'' AND ANY
* EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
* WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL UNITEDHEROES.NET BE LIABLE FOR ANY
* DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
* (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
* LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
* ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
* SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

(function (undefined) {

   var ATTRIBUTE_KEYS = ['callback', 'consumer_key', 'nonce', 'signature_method', 'timestamp', 'token', 'verifier', 'version'];
   var NONCE_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

   /* getNonce adapted from OAuthSimple
     * A simpler version of OAuth
     *
     * author:     jr conlin
     * mail:       src@anticipatr.com
     * copyright:  unitedHeroes.net
     * version:    1.2
     * url:        http://unitedHeroes.net/OAuthSimple
     *
     * Copyright (c) 2011, unitedHeroes.net
     *
    */

   function getNonce(length) {

      var length = length || 16,
          result = '',
          i=0,
          rnum,
          len = NONCE_CHARS.length;

      for ( ;i<length;i++ ) {
         rnum = Math.floor(Math.random() * len);
         result += NONCE_CHARS.substring(rnum, rnum+1);
      }

      return result;

   }

   function getTimestamp() {
      var d = new Date();

      return ''+Math.floor(d.getTime() / 1000);
   }

   // Global scope
   SimpleOAuth = {};

   var Header = function(method, url, params, oauth) {
      var oauth = oauth || {};

      this.method = method.toUpperCase();

      this.uri = URI.parseUri(url);
      this.uri.fragment = '';
      this.uri.normalize();

      this.params = params;
      this.options = _.extend(Header.default_options(), oauth);

   }

   Header.default_options = function () {
      return ({
             nonce: getNonce(),
             signature_method: 'HMAC-SHA1',
             timestamp: getTimestamp(),
             version: '1.0'
         });
   }

   /*
   *
   *  5.1.  Parameter Encoding
   *
   *  All parameter names and values are escaped using the [RFC3986] percent-encoding (%xx) mechanism.
   *  Characters not in the unreserved character set ([RFC3986] section 2.3) MUST be encoded. Characters
   *  in the unreserved character set MUST NOT be encoded. Hexadecimal characters in encodings MUST be upper
   *  case. Text names and values MUST be encoded as UTF-8 octets before percent-encoding them per [RFC3629].
   *
   *            unreserved = ALPHA, DIGIT, '-', '.', '_', '~'
   */

   Header.escape = function(value) {
      return encodeURIComponent(value)
               .replace(/\!/g, "%21")
               .replace(/\*/g, "%2A")
               .replace(/'/g, "%27")
               .replace(/\(/g, "%28")
               .replace(/\)/g, "%29");
   }

   Header.unescape = function(value) {
      return decodeURIComponent(value);
   }

   _.extend(Header.prototype, {


      /*
      *  Section 9.1.2 Construct Request URL
      *
      *  The Signature Base String includes the request absolute URL, tying the signature to a specific endpoint.
      *  The URL used in the Signature Base String MUST include the scheme, authority, and path, and MUST exclude the
      *  query and fragment as defined by [RFC3986] section 3.
      *
      *  If the absolute request URL is not available to the Service Provider (it is always available to the Consumer),
      *  it can be constructed by combining the scheme being used, the HTTP Host header, and the relative HTTP request URL.
      *  If the Host header is not available, the Service Provider SHOULD use the host name communicated to the Consumer
      *  in the documentation or other means.
      *
      *  The Service Provider SHOULD document the form of URL used in the Signature Base String to avoid ambiguity due to
      *  URL normalization. Unless specified, URL scheme and authority MUST be lowercase and include the port number; http
      *  default port 80 and https default port 443 MUST be excluded.
      *
      *  For example, the request:
      *
      *                  HTTP://Example.com:80/resource?id=123
      *
      *  Is included in the Signature Base String as:
      *
      *                  http://example.com/resource
      *
      *
      */

      url: function () {

         var uri = _.clone(this.uri);
         uri.query = null;
         return uri.build();

      },


      /*
      *  Section 7. Accessing Protected Resources
      *
      *  After successfully receiving the Access Token and Token Secret, the Consumer is able to access the
      *  Protected Resources on behalf of the User. The request MUST be signed per Signing Requests, and
      *  contains the following parameters:
      *
      *      oauth_consumer_key:
      *          The Consumer Key.
      *      oauth_token:
      *          The Access Token.
      *      oauth_signature_method:
      *          The signature method the Consumer used to sign the request.
      *      oauth_signature:
      *          The signature as defined in Signing Requests.
      *      oauth_timestamp:
      *          As defined in Nonce and Timestamp.
      *      oauth_nonce:
      *          As defined in Nonce and Timestamp.
      *      oauth_version:
      *          OPTIONAL. If present, value MUST be 1.0. Service Providers MUST assume the protocol version to be 1.0 if this parameter is not present. Service Providers’ response to non-1.0 value is left undefined.
      *      Additional parameters:
      *          Any additional parameters, as defined by the Service Provider.
      *
      *
      */

      build: function ( output ) {
         var output = output || 'header',
             s;

         if ( output == 'header' )
            s = 'OAuth ' + this.normalized_header_attributes(', ');
         else if ( output == 'query' )
            s = this.normalized_query_attributes('&');

         return s;
      },

      signed_attributes: function () {
         var attr = _.clone(this.attributes());
         attr['oauth_signature'] = this.signature();
         return attr;
      },

     // private

      normalized_header_attributes: function ( ) {

         return (
               _.map(
                  _.sortBy( _.pairs(this.signed_attributes()), function (v) { return v[0]; } ),
                     function (v) {
                           return v[0]+'="'+Header.escape(v[1])+'"';
                        }).join(', ')
            );
      },

      normalized_query_attributes: function ( ) {

         return (
               _.map(
                  _.sortBy( _.pairs(this.signed_attributes()), function (v) { return v[0]; } ),
                     function (v) {
                           return v[0]+'='+Header.escape(v[1]);
                        }).join('&')
            );
      },

      attributes: function() {
         var attr = {},
             opt = this.options;

         _.each(ATTRIBUTE_KEYS, function (k) {
               if (opt[k]) attr['oauth_'+k] = opt[k];
            });

         return attr;
      },

      /*
      *  9.  Signing Requests
      *
      *  All Token requests and Protected Resources requests MUST be signed by the Consumer and verified by the
      *  Service Provider. The purpose of signing requests is to prevent unauthorized parties from using the
      *  Consumer Key and Tokens when making Token requests or Protected Resources requests. The signature process
      *  encodes the Consumer Secret and Token Secret into a verifiable value which is included with the request.
      *
      *  OAuth does not mandate a particular signature method, as each implementation can have its own unique
      *  requirements. The protocol defines three signature methods: HMAC-SHA1, RSA-SHA1, and PLAINTEXT, but
      *  Service Providers are free to implement and document their own methods. Recommending any particular
      *  method is beyond the scope of this specification.
      *
      *  The Consumer declares a signature method in the oauth_signature_method parameter, generates a signature,
      *  and stores it in the oauth_signature parameter. The Service Provider verifies the signature as specified
      *  in each method. When verifying a Consumer signature, the Service Provider SHOULD check the request nonce
      *  to ensure it has not been used in a previous Consumer request.
      *
      *  The signature process MUST NOT change the request parameter names or values, with the exception of the
      *  oauth_signature parameter.
      */

      signature: function () {
         return this.hmac_sha1_signature();
      },

      hmac_sha1_signature: function () {
         return b64_hmac_sha1(this.secret(), this.signature_base());
      },

      /*
      *  9.2.  HMAC-SHA1
      *
      *  The HMAC-SHA1 signature method uses the HMAC-SHA1 signature algorithm as defined in [RFC2104] where the
      *  Signature Base String is the text and the key is the concatenated values (each first encoded per Parameter Encoding)
      *  of the Consumer Secret and Token Secret, separated by an ‘&’ character (ASCII code 38) even if empty.
      */

      secret: function () {
         var opt = _.pick(this.options, 'consumer_secret', 'token_secret');

         opt['consumer_secret'] = opt['consumer_secret'] || '';
         opt['token_secret'] = opt['token_secret'] || '';

         return _.map(opt, function (v) { return Header.escape(v); }).join('&');
      },


      /*
      *   9.1.3.  Concatenate Request Elements
      *
      *  The following items MUST be concatenated in order into a single string. Each item is encoded and separated
      *  by an ‘&’ character (ASCII code 38), even if empty.
      *
      *      The HTTP request method used to send the request. Value MUST be uppercase, for example: HEAD, GET , POST, etc.
      *      The request URL from Section 9.1.2.
      *      The normalized request parameters string from Section 9.1.1.
      *
      *  See Signature Base String example in Appendix A.5.1.
      */

      signature_base: function () {
        return _.map([this.method, this.url(), this.normalized_params()], function (v) { return Header.escape(v); }).join('&');
      },


      /*
      *  9.1.1.  Normalize Request Parameters
      *
      *  The request parameters are collected, sorted and concatenated into a normalized string:
      *
      *      Parameters in the OAuth HTTP Authorization header excluding the realm parameter.
      *      Parameters in the HTTP POST request body (with a content-type of application/x-www-form-urlencoded).
      *      HTTP GET parameters added to the URLs in the query part (as defined by [RFC3986] section 3).
      *
      *  The oauth_signature parameter MUST be excluded.
      *
      *  The parameters are normalized into a single string as follows:
      *
      *      Parameters are sorted by name, using lexicographical byte value ordering. If two or more parameters
      *      share the same name, they are sorted by their value. For example:
      *
      *                          a=1, c=hi%20there, f=25, f=50, f=a, z=p, z=t
      *
      *      Parameters are concatenated in their sorted order into a single string. For each parameter, the name is
      *      separated from the corresponding value by an ‘=’ character (ASCII code 61), even if the value is empty.
      *      Each name-value pair is separated by an ‘&’ character (ASCII code 38). For example:
      *
      *                          a=1&c=hi%20there&f=25&f=50&f=a&z=p&z=t
      *
      */

      normalized_params: function () {
         return (
            _.map(
               _.map(this.signature_params(), function (p) {
                  return _.map(p, function (v) {
                     return Header.escape(v);
                  })
               }).sort(), function (p) { return p.join('='); }).join('&')
            );
      },

      signature_params: function () {
         return _.pairs(this.attributes()).concat(_.pairs(this.params), this.url_params());
      },

      url_params: function () {
         var params = [];

         _.each(URI.parseQuery(this.uri.query || ''), function(vs, k) {
               params.push( _(_.flatten([vs]).sort()).chain().map(function (v) { return [k, v]; }).value() );
            });

         return _.flatten(params, true);
      }

   });

   SimpleOAuth.Header = Header;

   /*
   *  Need to have some URI utilities for parsing the URI and query string.
   *  This mimics some of the functionality provided by the Ruby URI and CGI
   *  modules
   */
   var _uri = function (parsed) {

      _.extend(this, parsed);

      this.default_port = '';
      switch (this.scheme) {

         case 'http' :
            this.default_port = '80';
            break;
         case 'https' :
            this.default_port = '443';
            break;

      }
   }
   _.extend(_uri.prototype, {

      normalize: function () {

         if ( this.path && this.path == '' )
            this.path = '/';

         if ( this.scheme && this.scheme != this.scheme.toLowerCase() )
            this.scheme = this.scheme.toLowerCase();

         if ( this.host && this.host != this.host.toLowerCase() )
            this.host = this.host.toLowerCase();

      },

      build: function () {
         var str = '';

         if ( this.scheme ) {
            str += this.scheme;
            str += ':';
         }

         if ( this.opaque ) {
            str += this.opaque;
         } else {

            if ( this.host )
              str += '//';

            if ( this.userinfo ) {
              str += this.userinfo;
              str += '@';
            }

            if ( this.host ) {
              str += this.host;
            }

            if ( this.port && this.port != this.default_port ) {
              str += ':';
              str += this.port;
            }

            str += this.path;

            if ( this.query ) {
               str += '?';
               str += this.query;
            }
         }

         if ( this.fragment ) {
            str += '#';
            str += this.fragment;
         }

         return str;
      }
   });

   URI = {

      /* Adapted from OAuthSimple
        * A simpler version of OAuth
        *
        * author:     jr conlin
        * mail:       src@anticipatr.com
        * copyright:  unitedHeroes.net
        * version:    1.2
        * url:        http://unitedHeroes.net/OAuthSimple
        *
        * Copyright (c) 2011, unitedHeroes.net
        *
       */

      parseQuery: function (query) {

         var elements = (query || "").split('&'),
             result={},
             element;

         for( element=elements.shift();element;element=elements.shift() ) {

            var keyToken=element.split('='),
                value='';

            if (keyToken[1]) {
               value=decodeURIComponent(keyToken[1]);
            }

            if(result[keyToken[0]]) {

               if (!(result[keyToken[0]] instanceof Array)) {
                  result[keyToken[0]] = Array(result[keyToken[0]], value);
               } else {
                 if ( _.isArray(result[keyToken[0]]) )
                    result[keyToken[0]].push(value);
                 else
                    result[keyToken[0]] = [result[keyToken[0]], value];
               }

            } else {
               result[keyToken[0]] = value;
            }
         }

         return result;

      },

      queryString: function (params) {
         return _.map(params, function (v,k) { return k+'='+encodeURIComponent(v); }).join('&');
      },

      // parseUri 1.2.2
      // (c) Steven Levithan <stevenlevithan.com>
      // MIT License

      parseUri: function (str) {
         var   o   = URI.options,
            m   = o.parser[o.strictMode ? "strict" : "loose"].exec(str),
            uri = {},
            i   = 14;

         while (i--) uri[o.key[i]] = m[i] || "";

         uri[o.q.name] = {};
         uri[o.key[12]].replace(o.q.parser, function ($0, $1, $2) {
            if ($1) uri[o.q.name][$1] = $2;
         });

         return new _uri(uri);
      },

      options: {
         strictMode: true,
         key: ["source","scheme","authority","userinfo","user","password","host","port","relative","path","directory","file","query","fragment"],
         q:   {
            name:   "queryKey",
            parser: /(?:^|&)([^&=]*)=?([^&]*)/g
         },
         parser: {
            strict: /^(?:([^:\/?#]+):)?(?:\/\/((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?))?((((?:[^?#\/]*\/)*)([^?#]*))(?:\?([^#]*))?(?:#(.*))?)/,
            loose:  /^(?:(?![^:@]+:[^:@\/]*@)([^:\/?#.]+):)?(?:\/\/)?((?:(([^:@]*)(?::([^:@]*))?)?@)?([^:\/?#]*)(?::(\d*))?)(((\/(?:[^?#](?![^?#\/]*\.[^?#\/.]+(?:[?#]|$)))*\/?)?([^?#\/]*))(?:\?([^#]*))?(?:#(.*))?)/
         }
      }

   }

   function b64_hmac_sha1(k,d,_p,_z){
   // heavily optimized and compressed version of http://pajhome.org.uk/crypt/md5/sha1.js
   // _p = b64pad, _z = character size; not used here but I left them available just in case
   if(!_p){_p='=';}if(!_z){_z=8;}function _f(t,b,c,d){if(t<20){return(b&c)|((~b)&d);}if(t<40){return b^c^d;}if(t<60){return(b&c)|(b&d)|(c&d);}return b^c^d;}function _k(t){return(t<20)?1518500249:(t<40)?1859775393:(t<60)?-1894007588:-899497514;}function _s(x,y){var l=(x&0xFFFF)+(y&0xFFFF),m=(x>>16)+(y>>16)+(l>>16);return(m<<16)|(l&0xFFFF);}function _r(n,c){return(n<<c)|(n>>>(32-c));}function _c(x,l){x[l>>5]|=0x80<<(24-l%32);x[((l+64>>9)<<4)+15]=l;var w=[80],a=1732584193,b=-271733879,c=-1732584194,d=271733878,e=-1009589776;for(var i=0;i<x.length;i+=16){var o=a,p=b,q=c,r=d,s=e;for(var j=0;j<80;j++){if(j<16){w[j]=x[i+j];}else{w[j]=_r(w[j-3]^w[j-8]^w[j-14]^w[j-16],1);}var t=_s(_s(_r(a,5),_f(j,b,c,d)),_s(_s(e,w[j]),_k(j)));e=d;d=c;c=_r(b,30);b=a;a=t;}a=_s(a,o);b=_s(b,p);c=_s(c,q);d=_s(d,r);e=_s(e,s);}return[a,b,c,d,e];}function _b(s){var b=[],m=(1<<_z)-1;for(var i=0;i<s.length*_z;i+=_z){b[i>>5]|=(s.charCodeAt(i/8)&m)<<(32-_z-i%32);}return b;}function _h(k,d){var b=_b(k);if(b.length>16){b=_c(b,k.length*_z);}var p=[16],o=[16];for(var i=0;i<16;i++){p[i]=b[i]^0x36363636;o[i]=b[i]^0x5C5C5C5C;}var h=_c(p.concat(_b(d)),512+d.length*_z);return _c(o.concat(h),512+160);}function _n(b){var t="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",s='';for(var i=0;i<b.length*4;i+=3){var r=(((b[i>>2]>>8*(3-i%4))&0xFF)<<16)|(((b[i+1>>2]>>8*(3-(i+1)%4))&0xFF)<<8)|((b[i+2>>2]>>8*(3-(i+2)%4))&0xFF);for(var j=0;j<4;j++){if(i*8+j*6>b.length*32){s+=_p;}else{s+=t.charAt((r>>6*(3-j))&0x3F);}}}return s;}function _x(k,d){return _n(_h(k,d));}return _x(k,d);
   }

})();
