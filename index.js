import http from 'axios'

const SIMPLEOTP_USER_PREFIX = 'simpleotp_user'
const SIMPLEOTP_CODE_PARAM_NAME = 'simpleotp_code'
const SIMPLEOTP_WEBAUTHN_SESSION_ID_HEADER_KEY = 'X-Simple-OTP-Web-Authn-Session-ID'
const DEFAULT_API_URL = 'https://api.simpleotp.com'

const NETWORKING_ERROR_MESSAGE = 'Could not connect to the server. Try again in a few moments.'
const INTERNAL_CREDENTIAL_ERROR_MESSAGE = 'An internal error occurred while fetching your passkeys. Your browser or security settings may not support passkeys.'
const CREDENTIAL_NOT_SELECTED_ERROR_MESSAGE = 'It seems you did not select a passkey, so the request was aborted.'

export const SignInStatusCode = Object.freeze({
  OK: Symbol('ok'),
  Unauthorized: Symbol('unauthorized'),
  InvalidEmail: Symbol('invalid_email'),
  InternalServerError: Symbol('internal_server_error'),
  InvalidSite: Symbol('invalid_site'),
  SiteNotFound: Symbol('site_not_found'),
  NetworkingError: Symbol('networking_error')
})

export const SiteWebAuthnStatusCode = Object.freeze({
  // Server generated status codes
  OK: Symbol('ok'),
  Unauthorized: Symbol('unauthorized'),
  InvalidEmail: Symbol('invalid_email'),
  InternalServerError: Symbol('internal_server_error'),
  InvalidSite: Symbol('invalid_site'),
  SiteNotFound: Symbol('site_not_found'),
  NetworkingError: Symbol('networking_error'),

  // Client generated status codes
  CredentialNotSelected: Symbol('credential_not_selected'),
  InternalCredentialError: Symbol('internal_credential_error'),
})

export const AuthStatusCode = Object.freeze({
  OK: Symbol('ok'),
  CodeNotFound: Symbol('code_not_found'),
  InvalidAuthCode: Symbol('invalid_auth_code'),
  InternalServerError: Symbol('internal_server_error'),
  NetworkingError: Symbol('networking_error')
})

export class AuthenticatedUser {
  /**
   * @param {string} id
   * @param {string} email 
   * @param {string} token 
   */
  constructor (id, email, token) {
    this.id = id
    this.email = email
    this.token = token
  }
}

class SiteSignInResponse {
  constructor(code, message) {
    this.code = code
    this.message = message
  }
}

class SiteAuthResponse {
  constructor(code, message, data) {
    this.code = code
    this.message = message
    this.data = data
  }
}

class SiteFinishWebAuthnLoginResponse {
  constructor(code, message, data) {
    this.code = code
    this.message = message
    this.data = data
  }
}

class SiteFinishWebAuthnRegistrationResponse {
  constructor(code, message, data) {
    this.code = code
    this.message = message
    this.data = data
  }
}

function isValidURL(urlString) {
  try { 
    return Boolean(new URL(urlString))
  } catch (e) { 
    return false
  }
}

function isWebAuthnSupported() {
  return Boolean(typeof(PublicKeyCredential) !== 'undefined' && navigator.credentials)
}

/**
 *
 * @param {ArrayBuffer} arrayBuffer 
 * @returns {string}
 */
function arrayBufferToBase64URLEncoded(arrayBuffer) {
  var bytes = new Uint8Array(arrayBuffer)
  var binary = ''
  for (var byte of bytes) {
      binary += String.fromCharCode(byte)
  }
  var base64 = btoa(binary)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/**
 * 
 * @param {PublicKeyCredential} credential
 * @returns {Object}
 */
function registrationCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64URLEncoded(credential.rawId),
    response: {
      attestationObject: arrayBufferToBase64URLEncoded(credential.response.attestationObject),
      clientDataJSON: arrayBufferToBase64URLEncoded(credential.response.clientDataJSON)
    },
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults()
  }
}

/**
 * 
 * @param {PublicKeyCredential} credential
 * @returns {Object}
 */
function loginCredentialToJSON(credential) {
  return {
    id: credential.id,
    rawId: arrayBufferToBase64URLEncoded(credential.rawId),
    response: {
      authenticatorData: arrayBufferToBase64URLEncoded(credential.response.authenticatorData),
      clientDataJSON: arrayBufferToBase64URLEncoded(credential.response.clientDataJSON),
      signature: arrayBufferToBase64URLEncoded(credential.response.signature),
      userHandle: arrayBufferToBase64URLEncoded(credential.response.userHandle)
    },
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment,
    clientExtensionResults: credential.getClientExtensionResults()
  }
}

export class SimpleOTP {
  constructor(siteID, apiURL = null) {
    if (!siteID || typeof(siteID) !== 'string') {
      throw Error('siteID must be a non-empty string')
    }

    if (apiURL && !isValidURL(apiURL)) {
      throw Error('apiURL must be a valid URL if defined')
    }

    this.siteID = siteID
    this.simpleOTPUserKey = `${SIMPLEOTP_USER_PREFIX}:${this.siteID}`
    if (apiURL) {
      this.apiURL = apiURL
    } else {
      this.apiURL = DEFAULT_API_URL
    }
  }

  /** 
   * Sends a magic sign-in link to the given email address
   * Note that this method does not authenticate the user - the user has to click the magic link and you must call authWithURLCode() when your authentication page loads.
   * @returns {Promise<SiteSignInResponse>}
   */
  async signIn(email) {
    if (!email || typeof(email) !== 'string') {
      throw Error('email must be a non-empty string')
    }

    try {
      const response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/sign-in`, { email })
      const responseData = response.data
      return new SiteSignInResponse(responseData.code, responseData.message)
    } catch (e) {
      const responseData = e.response?.data
      if (responseData) {
        return new SiteSignInResponse(responseData.code, responseData.message)
      } else {
        return new SiteSignInResponse(SignInStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE)
      }
    }
  }

  /** 
   * Completes the WebAuthn registration flow by starting a registration session with the server, creating credentials on the client, and sending the credentials back to the server
   * @returns {Promise<SiteFinishWebAuthnRegistrationResponse>}
   */
  async registerWebAuthnCredentials() {
    if (!isWebAuthnSupported()) {
      throw Error('WebAuthn is not supported in this browser')
    }

    // Start a registration session
    let options = null
    let sessionID = null

    const user = this.getUser()
    if (!user) {
      throw Error('You must be authenticated to register WebAuthn credentials')
    }

    const startRegistrationRequestHeaders = {'Authorization': `Bearer ${user.token}`}

    try {
      const response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/web-authn/registration-sessions/start`, null, { 
        headers: startRegistrationRequestHeaders
      })
      options = response.data
      sessionID = response.headers.get(SIMPLEOTP_WEBAUTHN_SESSION_ID_HEADER_KEY)
    } catch (e) {
      const responseData = e.response?.data
      if (responseData) {
        return new SiteFinishWebAuthnRegistrationResponse(responseData.code, responseData.message, null)
      } else {
        return new SiteFinishWebAuthnRegistrationResponse(SiteWebAuthnStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE, null)
      }
    }

    // The WebAuthn standard is poorly designed in that it requires a JavaScript ArrayBuffer to be used for all ids instead of a standard JSON data type. 
    // Handle this by converting each field that will barf on the client-side which is unfortunate but required as JavaScript types cannot be used on the server side.
    // For some reason only certain IDs like User ID and challenge are required to be in this format, and others like RP ID aren't. Why? Who knows. Maybe the WebAuthn authors were on hard drugs.
    const enc = new TextEncoder()
    options.publicKey.challenge = enc.encode(options.publicKey.challenge)
    options.publicKey.user.id = enc.encode(options.publicKey.user.id)

    // Create some credentials in the browser
    let selectedCredential = null
    try {
      selectedCredential = await navigator.credentials.create(options)
    } catch (e) {
        // Handle internal errors with the authenticator that aren't just the user canceling the request (NotAllowedError)
        if (e.name !== 'NotAllowedError') {
          console.error(e)
          return new SiteFinishWebAuthnRegistrationResponse(SiteWebAuthnStatusCode.InternalCredentialError.description, INTERNAL_CREDENTIAL_ERROR_MESSAGE, null)
        }
    }

    if (!selectedCredential) {
      return new SiteFinishWebAuthnRegistrationResponse(SiteWebAuthnStatusCode.CredentialNotSelected.description, CREDENTIAL_NOT_SELECTED_ERROR_MESSAGE, null)
    }

    // Register these credentials with the server so that they can be used for login authentication later
    const finishRegistrationRequestHeaders = Object.assign({}, startRegistrationRequestHeaders)
    finishRegistrationRequestHeaders[SIMPLEOTP_WEBAUTHN_SESSION_ID_HEADER_KEY] = sessionID

    const credentialJSON = registrationCredentialToJSON(selectedCredential)

    try {
      const response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/web-authn/registration-sessions/finish`, credentialJSON, {
        headers: finishRegistrationRequestHeaders
      })
      const responseData = response.data
      return new SiteFinishWebAuthnRegistrationResponse(responseData.code, responseData.message, responseData.data)
    } catch (e) {
      const responseData = e.response?.data
      if (responseData) {
        return new SiteFinishWebAuthnRegistrationResponse(responseData.code, responseData.message, null)
      } else {
        return new SiteFinishWebAuthnRegistrationResponse(SiteWebAuthnStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE, null)
      }
    }
  }

  /** 
   * Completes the WebAuthn auth flow by starting a login session with the server, finding credentials on the client, and sending the credentials back to the server
   * @returns {Promise<SiteFinishWebAuthnLoginResponse>}
   */
  async authWithWebAuthnCredentials(email) {
    if (!isWebAuthnSupported()) {
      throw Error('WebAuthn is not supported in this browser')
    }

    if (!email || typeof(email) !== 'string') {
      throw Error('email must be a non-empty string')
    }

    // Start login session
    let options = null
    let sessionID = null
    try {
      const response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/web-authn/login-sessions/start`, { email })
      options = response.data
      sessionID = response.headers.get(SIMPLEOTP_WEBAUTHN_SESSION_ID_HEADER_KEY)
    } catch (e) {
      const responseData = e.response?.data
      if (responseData) {
        return new SiteFinishWebAuthnLoginResponse(responseData.code, responseData.message, null)
      } else {
        return new SiteFinishWebAuthnLoginResponse(SiteWebAuthnStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE, null)
      }
    }

    const enc = new TextEncoder()
    options.publicKey.challenge = enc.encode(options.publicKey.challenge)

    // HACK: Credential whitelisting doesn't seem to work in Chrome. It can't find the credential given the ID even if it matches. For now, disable this on the client.
    options.publicKey.allowCredentials = []

    // Ask the user to select some matching credentials in the browser
    let selectedCredential = null
    try {
      selectedCredential = await navigator.credentials.get(options)
    } catch (e) {
      // Handle internal errors with the authenticator that aren't just the user canceling the request (NotAllowedError)
      if (e.name !== 'NotAllowedError') {
        console.error(e)
        return new SiteFinishWebAuthnLoginResponse(SiteWebAuthnStatusCode.InternalCredentialError.description, INTERNAL_CREDENTIAL_ERROR_MESSAGE, null)
      }
    }

    if (!selectedCredential) {
      return new SiteFinishWebAuthnLoginResponse(SiteWebAuthnStatusCode.CredentialNotSelected.description, CREDENTIAL_NOT_SELECTED_ERROR_MESSAGE, null)
    }

    const finishLoginHeaders = {}
    finishLoginHeaders[SIMPLEOTP_WEBAUTHN_SESSION_ID_HEADER_KEY] = sessionID

    const credentialJSON = loginCredentialToJSON(selectedCredential)

    // Try to auth with the credentials that were selected
    let response = null
    try {
      response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/web-authn/login-sessions/finish`, credentialJSON, {
        headers: finishLoginHeaders
      })
    } catch (e) {
      const responseData = e.response?.data
      if (responseData) {
        return new SiteFinishWebAuthnLoginResponse(responseData.code, responseData.message, null)
      } else {
        return new SiteFinishWebAuthnLoginResponse(SiteWebAuthnStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE, null)
      }
    }

    const httpResponseData = response.data
    const apiResponseData = httpResponseData.data
    const user = new AuthenticatedUser(apiResponseData.id, apiResponseData.email, apiResponseData.token)
    localStorage.setItem(this.simpleOTPUserKey, JSON.stringify(user))
    return new SiteFinishWebAuthnLoginResponse(httpResponseData.code, httpResponseData.message, httpResponseData.data)
  }

  /**
   * Authenticates a user based on the code supplied in the URL and returns a User with an auth token if the code was found.
   * The User is also saved in localStorage so that you can reference it elsewhere in the app. Use getUser() for this purpose.
   * @returns {Promise<SiteAuthResponse>}
   */
  async authWithURLCode() {
    const urlParams = new URLSearchParams(window.location.search)
    const code = urlParams.get(SIMPLEOTP_CODE_PARAM_NAME)
    if (!code) {
      throw Error(SIMPLEOTP_CODE_PARAM_NAME + ' was not found in the url params.')
    }

    return await this.auth(code)
  }

  /**
   * Authenticates a user based on the code param passed to this method.
   * The User is also saved in localStorage so that you can reference it elsewhere in the app. Use getUser() for this purpose.
   * @param {string} code 
   * @returns {Promise<SiteAuthResponse>}
   */
    async auth(code) {
      if (!code) {
        throw Error('code must be specified to use the auth method')
      }
  
      let response = null
      try { 
        response = await http.post(`${this.apiURL}/v1/sites/${this.siteID}/auth`, { code })
      } catch(e) {
        const errorHTTPResponseData = e.response?.data
        if (errorHTTPResponseData) {
          return new SiteAuthResponse(errorHTTPResponseData.code, errorHTTPResponseData.message, errorHTTPResponseData.data)
        } else {
          return new SiteAuthResponse(AuthStatusCode.NetworkingError.description, NETWORKING_ERROR_MESSAGE, null)
        }
      }
  
      const httpResponseData = response.data
      const apiResponseData = httpResponseData.data
      const user = new AuthenticatedUser(apiResponseData.id, apiResponseData.email, apiResponseData.token)
      localStorage.setItem(this.simpleOTPUserKey, JSON.stringify(user))
      return new SiteAuthResponse(httpResponseData.code, httpResponseData.message, httpResponseData.data)
    }

  /**
   * Fetches the currently authenticated user, if any, from localStorage and returns it. If there isn't an authenticated user,
   * this function returns null.
   * @returns {AuthenticatedUser}
   */
  getUser() {
    const user = localStorage.getItem(this.simpleOTPUserKey)
    if (!user) {
      return null
    }
    const userObj = JSON.parse(user)
    return new AuthenticatedUser(userObj.id, userObj.email, userObj.token)
  }

  /**
   * Returns true if the user is authenticated, false otherwise.
   * @returns {Boolean}
   */
  isAuthenticated() {
    return Boolean(localStorage.getItem(this.simpleOTPUserKey))
  }

  /**
   * Removes the User from localStorage, thereby signing the user out.
   */
  signOut() {
    localStorage.removeItem(this.simpleOTPUserKey)
  }
}