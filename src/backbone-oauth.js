(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD.
        define(['jquery', 'underscore', 'backbone', 'base', 'simple-oauth'], factory);
    } else {
        // Browser globals
        root.Backbone.OAuth = factory(root.$, root._, root.Backbone, Base, SimpleOAuth);
    }
}(this, function ($, _, Backbone, Base, SimpleOAuth) {

   var AuthManager = (function() {

         var _registry = {};

         function rewrite( base, path ) {

            var uri = URI.parseUri( path ),
                query;

            if ( uri.query ) {
               // queries with space are converting to +, not %20
               // server will see %20 for a space, so clean that up here
               uri.query = URI.queryString( URI.parseQuery( uri.query.replace( /\+/g, ' ' ) ) );
               path = uri.build();
            }

            if ( !base ) return path;

            var bsl = base.split( '/' ).reverse(),
                psl = path.split( '/' ),
                fn = [], idx = 0;

            bsl = _.compact( _.filter( bsl, function( p ) { return p.length > 0 ? p : null; } ) );
            psl = _.compact( _.filter( psl, function( p ) { return p.length > 0 ? p : null; } ) );

            _.each( bsl, function( b ) {
               if ( b != psl[idx] )
                  fn.unshift( b );
               else
                  idx++;
            });

            fn.push.apply( fn, psl );

            return '/'+fn.join( '/' );
         }

         function resolve( path ) {
            return (
               _.chain(_registry)
                  .filter( function (oa, ns) {
                        var test = rewrite( oa.basepath, path );
                        return test.indexOf('/'+ns) > -1;
                     })
                  .first()
                  .value()
              );
         }

         function inject(jqXHR, settings, auth) {

            var base = location.protocol + '//' + location.host,
                request = {
                     type: settings.type,
                     path: base,
                     url: rewrite( auth.basepath, settings.url ),
                     data: (settings.contentType.indexOf('application/x-www-form-urlencoded') > -1 ? URI.parseQuery(settings.data || '') : null),
                     headers: {}
                  };

            auth.build.apply( auth, [request] );

            // In case it was modified
            settings.url = request.url;

            _.each(request.headers, function ( v, k ) {
                  jqXHR.setRequestHeader(k, v);
               });
         }

         $.ajaxSetup({ beforeSend:
               function ( jqXHR, settings ) {

                  var oa = resolve(settings.url);
                  if ( oa ) {
                     inject( jqXHR, settings, oa );
                  }
               }
            });


         $(document).ajaxError(
               function(event, jqXHR, settings, exception) {

                  if ( jqXHR.status != 200 ) {
                     var oa = resolve(settings.url);
                     if ( oa ) {
                        oa.rescue( jqXHR.status );
                     }
                  }

               });

         var M = function () {};

         M.prototype.register = function (oa) {
            _registry[oa.namespace] = oa;
         }

         M.prototype.unregister = function (oa) {
            delete _registry[oa.namespace];
         }

         return new M();

      })();

   function detectOptionsFromURL() {
      var uri = URI.parseUri(location.href);

      return extractOptionsFromString(uri.query);
   }


   function removeOptionsFromURL() {
      var uri = URI.parseUri(location.href),
          filtered;

      filtered = _.chain(URI.parseQuery(uri.query) || {}).pairs().filter(function (p) { return p[0].indexOf('oauth_') == -1; }).object().value();
      uri.query = URI.queryString(filtered);

      return uri.build();
   }

   function extractOptionsFromString(resp) {
      return _.chain(URI.parseQuery(resp) || {}).pairs().map(function (p) { return [ p[0].replace(/^[x]?oauth_/, ''), p[1] ]}).object().value()
   }



   Backbone.OAuth = Base.extend([Backbone.Events], {

      constructor: function ( options ) {
         var options = options || {};

         this.initialize(options);
      },

      /*
      *  Make sure all requests have this path prepended.
      *  Merges the current path to ensure no duplication.
      *
      */
      basepath: null,

      /*
      *  Set these to the correct end-point for the service
      *  being accessed.
      *
      */
      namespace: null,

      /*
      *  This stores the consumer and owner keys.  The consumer
      *  keys must be set before
      *
      */
      keys: null,

      /*
      *  Set these to the correct end-point for the service
      *  being accessed.
      *
      */
      urls: null,

      /*
      *  Place the OAuth arguments in the Authorization header
      *  or in the URL query string.
      *
      */
      scheme: null,

      /*
      *  Full path to API to use in signing request.  Depending
      *  on if you are proxying requests, you may need to
      *  set this to ensure requests will be signed properly.
      *  Leave null to fall back to the base site the page
      *  is loaded to
      *
      */
      site: null,

      /*
      *  When signing requests, remove the matching expression
      *  from the path.  These most likely will be the namespace
      *  hook but depending on the end-point, might need some
      *  customization.  This can be a regex.  Defaults to namespace.
      *
      */
      rewrite: null,


      /*
      *  Error response codes that are oauth related
      *
      */
      errors: null,


      /*
      *  Handles the details of maintaining/building OAuth
      *  parameters and decoupling the details of provider
      *  specific data or variations in spec versions
      *
      */
      adapter: null,


      /*
      *  Force authorization cycle to begin at the beginning.
      *
      */
      reset: function ( silent ) {
         this.state = 1;
         this.keys.token = this.keys.token_secret = '';
         this.persist();
         this.prepare();

         if ( !silent )
            this.trigger('oauth:reset');
      },

      /*
      *  Determine if the authorization process is complete
      *  and protected services are available using the
      *  user context established by returned the token
      *
      */
      authorized: function () {
         return ( this.state == 4 &&
                  this.keys.token.length > 0 &&
                  this.keys.token_secret.length > 0 )
      },

      authorizing: function () { return this.state != 1 && !this.authorized(); },

      /*
      *  State machine.  Push through the authentication
      *  negotation process.
      *
      */
      authorize: function () {

         switch (this.state) {

            case 1:
               this.request_token();
               break;

            case 2:
               this.confirm();
               break;

            case 3:
               this.access_token();
               break;

            case 4:
               this.complete();
               break;
         }
      },

      // private

      state: 1,

      /*
      *  Set up options and go ...
      *
      */
      initialize: function ( options ) {

         this.keys = options.keys;
         this.urls = options.urls || {};
         this.namespace = options.namespace;
         this.basepath = options.basepath;
         this.errors = options.errors || []; //400, 401
         this.scheme = options.scheme || 'header';
         this.rewrite = options.rewrite || '/'+this.namespace;
         this.site = options.site;
         this.adapter = options.adapter || new Backbone.OAuth.Adapter();

         if (this.keys && this.namespace) {
            this.restore();
            this.setup();
            this.prepare();
         }
      },

      setup: function () {
         AuthManager.register(this);
      },

      reload: function() {
         if (this.keys && this.namespace) {
            this.restore();
            this.prepare();
            this.trigger( 'oauth:ready', this.adapter.data() );
         }
      },

      /*
      *  As generically as possible, execute each step in the
      *  authorization flow.
      *
      */

      request_token: function () {
         var that = this;

         this.prepare();

         $.ajax({
                url: this.urls.request,
                type: "POST",
                processData: false
              })
             .done( function (data, textStatus, jqXHR) {
                     that.update(extractOptionsFromString(data));
                     that.state++;
                     that.persist();
                     that.authorize();
                })
             .fail( function (jqXHR, textStatus, errorThrown) {
                     console.log('request_token failed '+jqXHR.status);
                     that.rescue( jqXHR.status );
                });

      },

      confirm: function () {

         var request = {
            url: this.urls.authorize
         }


         this.prepare();
         this.build( request );

         this.state++;
         this.persist();

         location.href = request.url;
      },

      access_token: function () {
         var that = this;

         this.prepare();

         $.ajax({
                url: this.urls.access,
                type: "POST",
                processData: false
              })
             .done( function (data, textStatus, jqXHR) {
                     that.update( extractOptionsFromString(data) );
                     that.state++;
                     that.persist();
                     that.authorize();
                })
             .fail( function (jqXHR, textStatus, errorThrown) {
                     console.log('access_token failed '+jqXHR.status);
                     that.rescue( jqXHR.status );
                });

      },

      complete: function () {

         var rd;

         if ( (rd = removeOptionsFromURL()) != location.href )
            location.href = rd;

         this.prepare();
         this.trigger( 'oauth:ready', this.adapter.data() );
      },

      renew_token: function () {
         var that = this;

         if ( !this.urls.renew ) {
            console.log('no renew!');
            this.reset();
            return;
         }

         this.prepare();

         $.ajax({
                url: this.urls.renew,
                type: "POST",
                processData: false
              })
             .done( function (data, textStatus, jqXHR) {
                     that.update( extractOptionsFromString(data) );
                     that.persist();
                     that.authorize();
                })
             .fail( function (jqXHR, textStatus, errorThrown) {
                     if ( $.inArray( jqXHR.status, that.errors ) )
                        console.log('failed renew!');
                        that.reset();
                });

      },

      rescue: function ( error ) {

         console.log('rescuing '+error);
         if ( _.contains( this.errors, error ) ) {
            if ( this.authorized() ) {
               this.renew_token();
            } else {
               console.log('rescue - authorizing!');
               this.reset();
            }
         } else if ( this.authorizing() ) {
            this.trigger('oauth:failure');
         }

      },

      /*
      *  Handle persisting state and basic functions called in the
      *  steps to collect/return data involved in the OAuth exchange
      *  Adapters further decouple the processing with specific details
      *  of each implementation.
      *
      */
      restore: function () {

         var dm = ['token', 'token_secret', 'state'].concat(this.adapter.persistent_data),
             df = Array(dm.length),
             ss = sessionStorage[this.keys.consumer_key] || df.join('&'),
             db = _.map(ss.split('&'), function (v) { return v.length > 0 ? v : null; }),
             data = _.object( dm, db );

         this.state = +data.state || 1;
         _.extend(this.keys, _.pick( data, 'token', 'token_secret' ) );

         this.adapter.data( _.omit(data, 'token', 'token_secret', 'state') );

      },

      persist: function () {

         var data = _.flatten([_.values(_.pick(this.keys, 'token', 'token_secret')), this.state, _.values(this.adapter.data())]);

         sessionStorage[this.keys.consumer_key] = _.map(data, function (v) { return v; }).join('&');
      },

      prepare: function () {

         var params = _.clone(this.keys);

         this.adapter.prepare( this.state, params );

      },

      update: function ( params ) {

         _.extend(this.keys, _.pick(params, 'consumer_key', 'consumer_secret', 'token', 'token_secret'));

         this.adapter.update( this.state, params );

      },

      build: function ( request ) {

         var rewrite = this.rewrite,
             header;

         request.auth_header = {};
         request.sign = false;

         this.adapter.build( this.state, request );

         if ( request.sign ) {

            header = new SimpleOAuth.Header(
                        request.type,
                        ( this.site || request.path ) + request.url.replace(rewrite, ''),
                        request.data,
                        request.auth_header);

            if ( this.scheme == 'header' )
               request.headers['Authorization'] = header.build( this.scheme );
            else if ( this.placement == 'query' )
               request.url += ( request.url.indexOf('?') > -1 ? '&' : '?') + header.build( this.scheme );

         }
      }

   });

   Backbone.OAuth.Adapters = {};

   /*
   *  Default adapter.  It should be sufficient for public-only
   *  usage.  Nothing will authorize using this adapter since
   *  it doesn't setup the owner tokens for signing requests.
   *
   *  saved_params is an option that be used to persist certain
   *  provider specific data (ie user ID) when no other customization
   *  is necessary.  Otherwise, this adapter (or one of its descendants)
   *  should be extended to implement the necessary behavior.
   *
   */

   Backbone.OAuth.Adapter = Base.extend({

      persistent_data: null,

      store: null,

      constructor: function ( options ) {
         var options = options || {};

         this.initialize( options );
      },

      initialize: function ( options ) {
         this.persistent_data = options.saved_params || [];
      },

      data: function ( data ) {

         if ( data) {
            this.store = _.extend(this.store || {}, data);
         } else {
            return _.pick.apply( this, _.flatten([this.store, this.persistent_data]) );
         }
      },

      prepare: function ( phase, params ) {
         this.store = _.extend(this.store || {}, params);
      },

      update: function ( phase, params ) {
         this.store = _.extend( this.store || {}, _.pick.apply( this, _.flatten([params, this.persistent_data]) ) );
      },

      build: function ( phase, request ) {

         request.sign = true;
         request.auth_header = _.pick(this.store, 'consumer_key', 'consumer_secret');

      }
   });


   /*
   *  Implement the specific requirements of OAuth 1.0 Rev A
   *
   */

   Backbone.OAuth.Adapters.v1revA = Backbone.OAuth.Adapter.extend({

      prepare: function ( phase, params ) {

         if ( phase == 1 ) {
            params = _.extend(params, { callback: removeOptionsFromURL() });
         }

         if ( phase == 3 ) {
            params = _.extend(params, detectOptionsFromURL());
         }

         this._super( phase, params );
      },

      build: function ( phase, request ) {

         if ( phase == 2 ) {

            request.url = request.url + '?oauth_token='+this.store.token;

         } else {

            request.sign = true;

            switch ( phase ) {

               case 1:
                  request.auth_header = _.pick(this.store, 'consumer_key', 'consumer_secret', 'callback');
                  break;

               case 3:
                  request.auth_header = _.pick(this.store, 'consumer_key', 'consumer_secret', 'token', 'token_secret', 'verifier');
                  break;

               case 4:
                  request.auth_header = _.pick(this.store, 'consumer_key', 'consumer_secret', 'token', 'token_secret');
                  break;
            }

         }
      }
   });


   return Backbone.OAuth;

}));
