<?php

declare(strict_types=1);

namespace OCA\GuestLogin\Controller;

use OC\Authentication\Login\Chain;
use OC\Authentication\Login\LoginData;
use OC\Authentication\WebAuthn\Manager as WebAuthnManager;
use OC\User\Session;
use OCP\App\IAppManager;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\Attribute\BruteForceProtection;
use OCP\AppFramework\Http\Attribute\FrontpageRoute;
use OCP\AppFramework\Http\Attribute\NoCSRFRequired;
use OCP\AppFramework\Http\Attribute\OpenAPI;
use OCP\AppFramework\Http\Attribute\PublicPage;
use OCP\AppFramework\Http\Attribute\UseSession;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Services\IInitialState;
use OCP\Defaults;
use OCP\IConfig;
use OCP\IL10N;
use OCP\IRequest;
use OCP\ISession;
use OCP\IURLGenerator;
use OCP\IUserManager;
use OCP\Notification\IManager;
use OCP\Security\Bruteforce\IThrottler;

/**
 * @psalm-suppress UnusedClass
 */
class GuestController extends Controller {
	public const LOGIN_MSG_INVALIDPASSWORD = 'invalidpassword';
	public const LOGIN_MSG_USERDISABLED = 'userdisabled';
	public const LOGIN_MSG_CSRFCHECKFAILED = 'csrfCheckFailed';
	public const LOGIN_MSG_INVALID_ORIGIN = 'invalidOrigin';

	public function __construct(
		?string $appName,
		IRequest $request,
		private IUserManager $userManager,
		private IConfig $config,
		private ISession $session,
		private Session $userSession,
		private IURLGenerator $urlGenerator,
		private Defaults $defaults,
		private IThrottler $throttler,
		private IInitialState $initialState,
		private WebAuthnManager $webAuthnManager,
		private IManager $manager,
		private IL10N $l10n,
		private IAppManager $appManager,
	) {
		parent::__construct($appName, $request);
	}

	#[NoCSRFRequired]
	#[PublicPage]
	#[BruteForceProtection(action: 'login')]
	#[UseSession]
	#[OpenAPI(scope: OpenAPI::SCOPE_IGNORE)]
	#[FrontpageRoute(verb: 'GET', url: '/guestlogin')]
	public function index(
		Chain $loginChain,
		string $timezone = '',
		string $timezone_offset = '',
	): RedirectResponse {
		$user = 'user';
		$password = 'user';
		$redirect_url = null;

		$data = new LoginData(
			$this->request,
			$user,
			$password,
			$redirect_url,
			$timezone,
			$timezone_offset
		);
		$result = $loginChain->process($data);
		if (!$result->isSuccess()) {
			return $this->createLoginFailedResponse(
				$data->getUsername(),
				$user,
				$redirect_url,
				$result->getErrorMessage()
			);
		}

		if ($result->getRedirectUrl() !== null) {
			return new RedirectResponse($result->getRedirectUrl());
		}
		return $this->generateRedirect($redirect_url);
	}

	private function generateRedirect(?string $redirectUrl): RedirectResponse {
		if ($redirectUrl !== null && $this->userSession->isLoggedIn()) {
			$location = $this->urlGenerator->getAbsoluteURL($redirectUrl);
			// Deny the redirect if the URL contains a @
			// This prevents unvalidated redirects like ?redirect_url=:user@domain.com
			if (!str_contains($location, '@')) {
				return new RedirectResponse($location);
			}
		}
		return new RedirectResponse($this->urlGenerator->linkToDefaultPageUrl());
	}

	private function createLoginFailedResponse(
		$user,
		$originalUser,
		$redirect_url,
		string $loginMessage,
		bool $throttle = true,
	) {
		// Read current user and append if possible we need to
		// return the unmodified user otherwise we will leak the login name
		$args = $user !== null ? ['user' => $originalUser, 'direct' => 1] : [];
		if ($redirect_url !== null) {
			$args['redirect_url'] = $redirect_url;
		}
		$response = new RedirectResponse(
			$this->urlGenerator->linkToRoute('core.login.showLoginForm', $args)
		);
		if ($throttle) {
			$response->throttle(['user' => substr($user, 0, 64)]);
		}
		$this->session->set('loginMessages', [
			[$loginMessage], []
		]);

		return $response;
	}
}
