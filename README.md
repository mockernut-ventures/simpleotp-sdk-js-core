# simpleotp-sdk-js-core

This is the core JavaScript-based authentication SDK for [Simple OTP](https://simpleotp.com), the easiest way to add passwordless authentication to your website.

Integration documentation varies depending on which frontend library you're using, see below:

# React: Docs and Component Examples
https://github.com/mockernut-ventures/simpleotp-sdk-js-react#readme

# Vue: Docs and Component Examples
https://github.com/mockernut-ventures/simpleotp-sdk-js-vue#readme

# Others
If you aren't using either of the above frameworks, you will just need to use this library by itself and write your own integration code. To install the library:
`npm i @simpleotp/core`

For examples of how to use the core library without the React or Vue plugin, see [here](https://github.com/mockernut-ventures/simpleotp-sdk-js-core/blob/main/__tests__/index.spec.js).

# Magic Link vs. Code-based Authentication
The only situation where we recommend Code-based authentication is when users cannot click a web URL to open your app. For example, progressive web apps (PWAs) have this problem and should use code based authentication. All other apps should use Magic Links.

# About Simple OTP
**We make integration easy for developers**:
Install our JavaScript SDK and integrate in just a few lines of code. With our pro plan, you can use our API and webhook events to automate tasks such as blacklisting users, creating sites, and updating account details.

**We obsess over privacy**:
The only data we collect from a signup is an email address, which is only used in a transactional fashion as a part of the passwordless sign-in process. Your users' email addresses are never shared with third party companies.

**We offer self-hosting**:
Host Simple OTP on your own servers and store user emails in your own database with the Pro plan. We'll also provide you with support if you need it.

**Our [pricing](https://simpleotp.com/#pricing-scrollpoint) is fair**:
We have consistent, flat-rate pricing with high enough user caps to allow you to operate a production website. Unlike the competition, we don't arbitrarily charge more based on what type of website or business you operate.
