<?php

declare(strict_types=1);
/**
 * SPDX-FileCopyrightText: 2020 Nextcloud GmbH and Nextcloud contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

namespace OCA\GuestLogin;

use OCP\Authentication\IAlternativeLogin;
use OCP\IURLGenerator;

class GuestLoginOption implements IAlternativeLogin {

	public function __construct(
		protected IURLGenerator $url,
		protected \OC_Defaults $theming,
	) {
	}

	public function getLabel(): string {
		return "Войти как студент";
	}

	public function getLink(): string {
		$params = [];
		$params['user'] = "user";
		// $params['password'] = "user";

		return $this->url->linkToRouteAbsolute('guestlogin.guest.index', $params);
	}

	public function getClass(): string {
		return 'single-alt-login-option';
	}

	public function load(): void {
	}
}
