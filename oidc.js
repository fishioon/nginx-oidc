// for debug.
function print(r) {
	r.headersOut['Content-Type'] = 'application/json'
	var res = {
		args: stringObject(r.args),
		headersIn: stringObject(r.headersIn),
		headersOut: stringObject(r.headersOut),
		vars: stringObject(r.variables)
	}
	r.error('connectors: ' + r.variables['connectors'])
	r.return(200, JSON.stringify(res))
}

function stringObject(o) {
	var _args = {}, arg
	for (arg in o) {
		_args[arg] = o[arg]
	}
	return JSON.stringify(_args)
}

function printLoginUser(r) {
	r.headersOut['Content-Type'] = 'application/json'
	r.return(200, "login user: " + r.headersIn['username'])
}

// oidc ==============================

// authRequest work with auth_request module
function authRequest(r) {
	var authToken = r.variables.auth_token || r.headersIn['Authorization']
	if (authToken) {
		r.variables['jwt_claim_sub'] = authToken
		r.return(200)
	} else {
		r.return(401)
	}
}

function hashRequestId(r) {
    var c = require('crypto');
    var h = c.createHmac('sha256', r.variables.oidc_hmac_key).update(r.variables.request_id);
    return h.digest('base64url');
}

function oidcCodeExchange(r) {
    // First check that we received an authorization code from the IdP
    if (r.variables.arg_code.length == 0) {
        if (r.variables.arg_error) {
            r.error("OIDC error receiving authorization code from IdP: " + r.variables.arg_error_description);
        } else {
            r.error("OIDC expected authorization code from IdP but received: " + r.variables.uri);
        }
        r.return(502);
        return;
    }

    // Pass the authorization code to the /_token location so that it can be
    // proxied to the IdP in exchange for a JWT
    r.subrequest("/_token", "code=" + r.variables.arg_code,
        function(reply) {
            if (reply.status == 504) {
                r.error("OIDC timeout connecting to IdP when sending authorization code");
                r.return(504);
                return;
            }

            if (reply.status != 200) {
                try {
                    var errorset = JSON.parse(reply.responseBody);
                    if (errorset.error) {
                        r.error("OIDC error from IdP when sending authorization code: " + errorset.error + ", " + errorset.error_description);
                    } else {
                        r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                    }
                } catch (e) {
                    r.error("OIDC unexpected response from IdP when sending authorization code (HTTP " + reply.status + "). " + reply.responseBody);
                }
                r.return(502);
                return;
            }

            try {
                var tokenset = JSON.parse(reply.responseBody);
                r.variables.auth_token = tokenset['id_token']; // Export as NGINX variable
								r.return(302, r.variables.cookie_auth_redir);
            } catch (e) {
                r.error("OIDC authorization code sent but token response is not JSON. " + reply.status + " " + reply.responseBody);
                r.return(502);
            }
        }
    );
}
