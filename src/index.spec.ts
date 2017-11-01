import { assert } from "chai";
import * as chai from "chai";
// tslint:disable-next-line:no-var-requires
chai.use(require("chai-as-promised"));
// import * as sinon from "sinon";

import { CognitoAuthProvider } from "./index";

import * as path from "path";
import * as superagent from "superagent";
import * as superagentMock from "superagent-mock";
import * as jwt from "jsonwebtoken";
import * as fs from "fs-extra";
import * as pemJwk from "pem-jwk";

import { TestServer, AuthService } from "realm-object-server";
import * as RealmProblem from "realm-object-server/dist/errors/RealmProblem";

describe("CognitoAuthProvider", () => {
    let provider: CognitoAuthProvider;
    let server: TestServer;
    let authService: AuthService;
    let mock;
    let privateKey1;
    let privateKey2;

    before(async () => {
        privateKey1 = await fs.readFile(path.join(__dirname, "..", "fixtures", "key1.key"));
        const publicKey1 = await fs.readFile(path.join(__dirname, "..", "fixtures", "key1.pub"));
        const jwk1 = pemJwk.pem2jwk(publicKey1);
        jwk1.kid = "key1";

        privateKey2 = await fs.readFile(path.join(__dirname, "..", "fixtures", "key2.key"));

        mock = superagentMock(superagent, [{
            pattern: "https://cognito-idp.eu-west-1.amazonaws.com(.*)",
            get: function get(match, data) {
                return {
                    code: 200,
                    body: data,
                };
            },
            fixtures: function fixtures(match, params, headers, context) {
                if (match[1] === "/myPoolId/.well-known/jwks.json") {
                    return {
                        keys: [jwk1],
                    };
                }
            },
        }]);

        server = new TestServer();
        provider = new CognitoAuthProvider({
            region: "eu-west-1",
            userPoolId: "myPoolId",
        });
        await server.start({
            authProviders: [ provider ],
        });
        authService = server.getService("auth");
    });

    after(async () => {
        if (server) {
            await server.shutdown().catch((err) => {
                //
            });
        }
        mock.unset();
    });

    describe("authenticateOrCreateUser", () => {
        describe("without data param", () => {
            it("should return a MissingParameters exception", async () => {
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ }),
                    RealmProblem.MissingParameters,
                );
            });
        });

        describe("with invalid data param", () => {
            it("should return an InvalidParameters exception", async () => {
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ data: "isInvalid" }),
                    RealmProblem.InvalidParameters,
                );
            });
        });

        describe("with real, but invalid token in data param", () => {
            it("should return an InvalidCredentials exception", async () => {
                const token = jwt.sign({ foo: "bar" }, "shhhhh");
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ data: token }),
                    RealmProblem.InvalidCredentials,
                );
            });
        });

        describe("with valid, but wrong access type token in data param", () => {
            it("should return an InvalidCredentials exception", async () => {
                const token = jwt.sign({
                    iss: "https://cognito-idp.eu-west-1.amazonaws.com/myPoolId",
                    token_use: "id",
                }, "shhhhh");
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ data: token }),
                    RealmProblem.InvalidCredentials,
                );
            });
        });

        describe("with valid, but wrong key id in data param", () => {
            it("should return an InvalidCredentials exception", async () => {
                const token = jwt.sign({
                    iss: "https://cognito-idp.eu-west-1.amazonaws.com/myPoolId",
                    token_use: "access",
                }, privateKey1, {
                    algorithm: "RS256",
                    header: { kid: "my-other-kid" },
                });
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ data: token }),
                    RealmProblem.InvalidCredentials,
                );
            });
        });

        describe("with valid, but wrong signature token in data param", () => {
            it("should return an InvalidCredentials exception", async () => {
                const token = jwt.sign({
                    iss: "https://cognito-idp.eu-west-1.amazonaws.com/myPoolId",
                    token_use: "access",
                }, privateKey2, {
                    algorithm: "RS256",
                    header: { kid: "key1" },
                });
                await assert.isRejected(
                    provider.authenticateOrCreateUser({ data: token }),
                    RealmProblem.InvalidCredentials,
                );
            });
        });

        describe("with valid token in data param", () => {
            it("should return a user", async () => {
                const token = jwt.sign({
                    iss: "https://cognito-idp.eu-west-1.amazonaws.com/myPoolId",
                    token_use: "access",
                    username: "Rod.Smith",
                }, privateKey1, {
                    algorithm: "RS256",
                    header: { kid: "key1" },
                });
                const user = await assert.isFulfilled(
                    provider.authenticateOrCreateUser({ data: token }),
                ) as any;
                assert.isDefined(user);
                assert.isTrue(user.created);
                assert.equal(user.accounts[0].providerId, "Rod.Smith");
            });
        });
    });
});
