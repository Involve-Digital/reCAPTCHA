<?php declare(strict_types = 1);

namespace Contributte\ReCaptcha;

use Nette\Forms\Controls\BaseControl;
use Nette\SmartObject;

/**
 * @method onValidateControl(ReCaptchaProvider $provider, BaseControl $control)
 * @method onValidate(ReCaptchaProvider $provider, mixed $response)
 */
class ReCaptchaProvider
{

	use SmartObject;

	// ReCaptcha FTW!
	public const FORM_PARAMETER = 'g-recaptcha-response';
	public const VERIFICATION_URL = 'https://www.google.com/recaptcha/api/siteverify';

	/** @var callable[] */
	public $onValidate = [];

	/** @var callable[] */
	public $onValidateControl = [];

	/** @var string */
	private $siteKey;

	/** @var string */
	private $secretKey;

    private $minimalScore;

    public function __construct(string $siteKey, string $secretKey, float $minimalScore = 0)
    {
        $this->siteKey = $siteKey;
        $this->secretKey = $secretKey;
        $this->setMinimalScore($minimalScore);
    }

	public function getSiteKey(): string
	{
		return $this->siteKey;
	}

	/**
	 * @param mixed $response
	 */
	public function validate($response): ?ReCaptchaResponse
	{
		// Fire events!
		$this->onValidate($this, $response);

		// Load response
		$response = $this->makeRequest($response);

		// Response is empty or failed..
		if (empty($response)) {
			return null;
		}

		// Decode server answer (with key assoc reserved)
		$answer = json_decode($response, true);

        // Return response
        return ($answer['success'] === true && ($this->minimalScore <= 0
                || !isset($answer['score']) || $answer['score'] >= $this->minimalScore))
            ? new ReCaptchaResponse(true)
            : new ReCaptchaResponse(false, $answer['error-codes'] ?? null);
    }

	public function validateControl(BaseControl $control): bool
	{
		// Fire events!
		$this->onValidateControl($this, $control);

		// Get response
		$response = $this->validate($control->getValue());

		if ($response !== null) {
			return $response->isSuccess();
		}

		return false;
	}

    public function setMinimalScore(float $score): void
    {
        $this->minimalScore = $score;
    }


	/**
	 * @param mixed $response
	 * @return mixed
	 */
	protected function makeRequest($response, ?string $remoteIp = null)
	{
		if (empty($response)) {
			return null;
		}

		$params = [
			'secret' => $this->secretKey,
			'response' => $response,
		];

		if ($remoteIp !== null) {
			$params['remoteip'] = $remoteIp;
		}

		return @file_get_contents($this->buildUrl($params));
	}

	/**
	 * @param mixed[] $parameters
	 */
	protected function buildUrl(array $parameters = []): string
	{
		return self::VERIFICATION_URL . '?' . http_build_query($parameters);
	}

}
