"use strict";
var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
exports.__esModule = true;
exports.OAuthAccessTokenExchangeFailedRequest = exports.AuthCodeAlreadyUsed = exports.WrongRedirectUri = exports.UserNotAuthenticatedError = exports.UnregisteredApplication = exports.WrongCredentialsError = void 0;
var WrongCredentialsError = /** @class */ (function (_super) {
    __extends(WrongCredentialsError, _super);
    function WrongCredentialsError() {
        return _super.call(this, 'There is no such user with the specified credentials') || this;
    }
    return WrongCredentialsError;
}(Error));
exports.WrongCredentialsError = WrongCredentialsError;
var UnregisteredApplication = /** @class */ (function (_super) {
    __extends(UnregisteredApplication, _super);
    function UnregisteredApplication() {
        return _super.call(this, 'the specified client id does not correspond to any registered application') || this;
    }
    return UnregisteredApplication;
}(Error));
exports.UnregisteredApplication = UnregisteredApplication;
var UserNotAuthenticatedError = /** @class */ (function (_super) {
    __extends(UserNotAuthenticatedError, _super);
    function UserNotAuthenticatedError() {
        return _super.call(this, 'User is not authenticated') || this;
    }
    return UserNotAuthenticatedError;
}(Error));
exports.UserNotAuthenticatedError = UserNotAuthenticatedError;
var WrongRedirectUri = /** @class */ (function (_super) {
    __extends(WrongRedirectUri, _super);
    function WrongRedirectUri() {
        return _super.call(this, 'the specified redirect_uri does not correspond to the registered one') || this;
    }
    return WrongRedirectUri;
}(Error));
exports.WrongRedirectUri = WrongRedirectUri;
var AuthCodeAlreadyUsed = /** @class */ (function (_super) {
    __extends(AuthCodeAlreadyUsed, _super);
    function AuthCodeAlreadyUsed() {
        return _super.call(this, 'the authorization code has already been used') || this;
    }
    return AuthCodeAlreadyUsed;
}(Error));
exports.AuthCodeAlreadyUsed = AuthCodeAlreadyUsed;
var OAuthAccessTokenExchangeFailedRequest = /** @class */ (function (_super) {
    __extends(OAuthAccessTokenExchangeFailedRequest, _super);
    function OAuthAccessTokenExchangeFailedRequest(httpError, error, errorDescription) {
        var _this = _super.call(this, 'access token exchange request failed') || this;
        _this.httpError = httpError;
        _this.error = error;
        _this.errorDescription = errorDescription;
        return _this;
    }
    Object.defineProperty(OAuthAccessTokenExchangeFailedRequest.prototype, "errorBody", {
        get: function () {
            return {
                error: this.error,
                error_description: this.errorDescription
            };
        },
        enumerable: false,
        configurable: true
    });
    return OAuthAccessTokenExchangeFailedRequest;
}(Error));
exports.OAuthAccessTokenExchangeFailedRequest = OAuthAccessTokenExchangeFailedRequest;
