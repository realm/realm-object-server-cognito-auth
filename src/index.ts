import * as RealmObjectServer from "realm-object-server";

import * as RealmProblem from "realm-object-server/dist/errors/RealmProblem";
import { User } from "realm-object-server/dist/realms/AdminRealm";

import * as jwt from "jsonwebtoken";
import * as superagent from "superagent";
import { jwk2pem } from "pem-jwk";

export interface CognitoAuthProviderConfiguration {
    region: string;
    userPoolId: string;
}

export class CognitoAuthProvider extends RealmObjectServer.auth.AuthProvider {
    name = "cognito";
    private pems: any;
    private iss: string;

    constructor(config: CognitoAuthProviderConfiguration) {
        super();

        if (config === undefined) {
            throw new Error("Missing argument: config");
        }
        if (config.region === undefined) {
            throw new Error("Missing argument: config.region");
        }
        if (config.userPoolId === undefined) {
            throw new Error("Missing argument: config.userPoolId");
        }

        this.iss = `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}`;
    }

    public async start() {
        this.pems = await this.obtainPems();
    }

    public async authenticateOrCreateUser(body) {
        // The token submitted by the client
        const token = body.data;
        if (!token) {
            throw new RealmProblem.MissingParameters("data");
        }

        // Fail if the token is not jwt
        const decodedJwt = jwt.decode(token, {
            complete: true,
        }) as any;

        if (!decodedJwt) {
            throw new RealmProblem.InvalidParameters({
                name: "data",
                reason: "is not a valid JWT.",
            });
        }

        // Fail if token is not from your User Pool
        if (decodedJwt.payload.iss !== this.iss) {
            throw new RealmProblem.InvalidCredentials();
        }

        // Reject the jwt if it's not an 'Access Token'
        if (decodedJwt.payload.token_use !== "access") {
            throw new RealmProblem.InvalidCredentials();
        }

        // Get the keyId from the token and retrieve corresponding PEM
        const keyId = decodedJwt.header.kid;
        const pem = this.pems[keyId];
        if (!pem) {
            throw new RealmProblem.InvalidCredentials();
        }

        // Verify the signature of the JWT token to ensure it's really coming from your User Pool
        const userId = await new Promise<string>((resolve, reject) => {
            jwt.verify(token, pem, { issuer: this.iss }, (err, payload: any) => {
                if (err) {
                    reject(new RealmProblem.InvalidCredentials());
                }
                resolve(payload.username);
            });
        });

        return this.service.createOrUpdateUser(
            userId,
            this.constructor.name,
            false,
            null,
        );
    }

    private async obtainPems() {
        // Download the JWKs and save it as PEM
        const response = await superagent.get(`${this.iss}/.well-known/jwks.json`);
        const pems = {};
        const keys = response.body.keys;

        for (const key of keys) {
            // Convert each key to PEM
            pems[key.kid] = jwk2pem({ kty: key.kty, n: key.n, e: key.e });
        }
        return pems;
    }
}
