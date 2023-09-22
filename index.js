import http from 'axios'

const SIMPLEOTP_USER_PREFIX = 'simpleotp_user'
const SIMPLEOTP_CODE_PARAM_NAME = 'simpleotp_code'
const DEFAULT_API_URL = 'https://api.simpleotp.com'

const NETWORKING_ERROR_MESSAGE = 'Could not connect to the server. Try again in a few moments.'

export const SignInStatusCode = Object.freeze({
  OK: Symbol('ok'),
  Unauthorized: Symbol('unauthorized'),
  InvalidEmail: Symbol('invalid_email'),
  InternalServerError: Symbol('internal_server_error'),
  InvalidSite: Symbol('invalid_site'),
  SiteNotFound: Symbol('site_not_found'),
  NetworkingError: Symbol('networking_error')
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

function isValidURL(urlString) {
  try { 
    return Boolean(new URL(urlString))
  } catch (e) { 
    return false
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
   * @returns {Promise<APIResponse>}
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