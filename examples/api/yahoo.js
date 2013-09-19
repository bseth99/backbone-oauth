
/*
https://api.login.yahoo.com/oauth/v2/get_request_token
https://api.login.yahoo.com/oauth/v2/request_auth
https://api.login.yahoo.com/oauth/v2/get_token


http://social.yahooapis.com/v1/me/guid
http://social.yahooapis.com/v1/user/{guid}/contacts
*/

   var ep = new Backbone.OAuth.v1revA({

         namespace: 'yahoo',

         keys: {
            consumer_key: 'dj0yJmk9RlR3eFFUNGR0Y2gzJmQ9WVdrOU5ubHhWMDVETTJVbWNHbzlOakV6T1RBME5UWXkmcz1jb25zdW1lcnNlY3JldCZ4PTQ0',
            consumer_secret: '70cdc0feee8f9bc8bdb7318d48d621f7127247fe'
         },

         urls: {
            request: '/yahoo/oauth/get_request_token',
            authorize: 'https://api.login.yahoo.com/oauth/v2/request_auth',
            access: '/yahoo/oauth/get_token'
         }
      });