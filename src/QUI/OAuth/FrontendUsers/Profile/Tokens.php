<?php

namespace QUI\OAuth\FrontendUsers\Profile;

use QUI;
use QUI\FrontendUsers\Controls\Profile\AbstractProfileControl;
use QUI\Interfaces\Users\User as QUIUserInterface;
use QUI\OAuth\FrontendController;
use QUI\OAuth\Permission;
use QUI\Utils\Security\Orthos;

use function dirname;

class Tokens extends AbstractProfileControl
{
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);

        $this->addCSSClass('quiqqer-oauth-server-profile-tokens');
        $this->addCSSClass('quiqqer-frontendUsers-controls-profile-control');
        $this->addCSSFile(dirname(__FILE__) . '/Tokens.css');
        $this->setJavaScriptControl('package/quiqqer/oauth-server/bin/frontend/controls/profile/Tokens');
    }

    /**
     * @throws QUI\Exception
     */
    public function getBody(): string
    {
        $Engine = QUI::getTemplateManager()->getEngine();
        $User = $this->getProfileUser();
        $frontendController = new FrontendController();

        $Engine->assign([
            'canManageOwnTokens' => $this->canManageOwnTokens($User),
            'tokens' => $frontendController->getPermanentAccessTokens($User)
        ]);

        return $Engine->fetch(dirname(__FILE__) . '/Tokens.html');
    }

    /**
     * @throws QUI\Exception
     * @throws QUI\OAuth\FrontendException
     */
    public function onSave(): void
    {
        $Request = QUI::getRequest()->request;
        $User = $this->getProfileUser();
        $action = Orthos::clear((string)$Request->get('oauthTokenAction'));
        $frontendController = new FrontendController();

        switch ($action) {
            case 'delete':
                $tokenId = Orthos::clear((string)$Request->get('oauthTokenId'));

                if (!empty($tokenId)) {
                    $frontendController->deletePermanentAccessToken($User, $tokenId);
                }
                break;

            case 'create':
            default:
                $title = trim((string)$Request->get('tokenTitle'));
                $frontendController->createPermanentAccessToken($User, $title);
        }
    }

    protected function getProfileUser(): QUIUserInterface
    {
        $User = $this->getAttribute('User');

        if ($User instanceof QUIUserInterface) {
            return $User;
        }

        return QUI::getUserBySession();
    }

    protected function canManageOwnTokens(QUIUserInterface $user): bool
    {
        return Permission::MANAGE_CLIENTS->has($user)
            || Permission::CREATE_PERMANENT_ACCESS_TOKEN_FOR_OWN_USER->has($user);
    }
}
