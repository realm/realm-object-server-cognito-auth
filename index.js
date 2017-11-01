const RealmObjectServer = require('realm-object-server');
const jwt = require('jsonwebtoken');
const request = require('request');
const jwkToPem = require('jwk-to-pem');


class CognitoProvider extends RealmObjectServer.auth.AuthProvider {
    constructor(iss) {
        super();
        this.name = 'cognito';

        if (!iss) {
            throw new RealmObjectServer.errors.RealmProblem.ServerMisconfiguration({
                detail: 'Missing cognito configuration key: iss',
            });
        }

        this.iss = iss;
    }

    authenticateOrCreateUser(body) {
        // The token submitted by the client
        const token = body.data;

        return this.obtainPems()
            .then((pems) => {
                // Fail if the token is not jwt
                var decodedJwt = jwt.decode(token, {
                    complete: true
                });

                if (!decodedJwt) {
                    throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                        title: 'The token sent by the client was not a valid JWT',
                    });
                }

                // Fail if token is not from your User Pool
                if (decodedJwt.payload.iss != this.options.iss) {
                    throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                        title: 'The token sent by the client was issued by the correct ISS',
                    });
                }

                // Reject the jwt if it's not an 'Access Token'
                if (decodedJwt.payload.token_use != 'access') {
                    throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                        title: 'The token sent by the client is not a valid access token',
                    });
                }

                // Get the keyId from the token and retrieve corresponding PEM
                var keyId = decodedJwt.header.kid;
                var pem = pems[keyId];

                if (!pem) {
                    throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                        title: 'The token sent by the client is not a valid access token',
                    });
                }

                // Verify the signature of the JWT token to ensure it's really coming from your User Pool
                jwt.verify(token, pem, {
                    issuer: this.options.iss
                }, (err, payload) => {
                    if (err) {
                        throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                            title: `Can't verify the JWT signature: ${err.toString()}`,
                        });
                    }
                    return this.service.createOrUpdateUser(
                        payload.username,
                        "cognito",
                        false,
                        null
                    );
                });
            });
    }


    obtainPems() {
        if (!this.pems) {
            // Download the JWKs and save it as PEM
            const httpOptions = {
                uri: `${this.options.iss}/.well-known/jwks.json`,
                method: 'GET',
                json: true,
            };

            return this.request(httpOptions)
                .catch((err) => {
                    throw new RealmObjectServer.errors.RealmProblem.InvalidCredentials({
                        title: `Unable to retrieve PEMs from Cognito: ${err.toString()}`,
                    });
                })
                .then((result) => {
                    this.pems = {};
                    var keys = result.keys;

                    for (var i = 0; i < keys.length; i++) {
                        // Convert each key to PEM
                        var key_id = keys[i].kid;
                        var modulus = keys[i].n;
                        var exponent = keys[i].e;
                        var key_type = keys[i].kty;
                        var jwk = { kty: key_type, n: modulus, e: exponent };
                        var pem = jwkToPem(jwk);

                        this.pems[key_id] = pem;
                    }

                    return this.pems;
                });
        }

        else {
            return Promise.resolve(this.pems);
        }
    }
}
