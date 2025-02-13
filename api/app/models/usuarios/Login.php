<?php

/*
 * This file is part of the Ocrend Framewok 3 package.
 *
 * (c) Ocrend Software <info@ocrend.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace app\models\usuarios;

use app\models\usuarios as Model;
use Ocrend\Kernel\Helpers as Helper;
use Ocrend\Kernel\Models\IModels;
use Ocrend\Kernel\Models\Models;
use Ocrend\Kernel\Models\ModelsException;
use Ocrend\Kernel\Router\IRouter;

/**
 * Modelo Login
 */
class Login extends Models implements IModels
{

    /**
     * Máximos intentos de inincio de sesión de un usuario
     *
     * @var int
     */
    const MAX_ATTEMPTS = 80;

    /**
     * Tiempo entre máximos intentos en segundos
     *
     * @var int
     */
    const MAX_ATTEMPTS_TIME = 300; # (300 => 5 minutos)

    /**
     * Log de intentos recientes con la forma 'email' => (int) intentos
     *
     * @var array
     */
    private $recentAttempts = array();

    # Variables de Clase
    private $usr = null;
    private $userMail = null;
    private $tokenUsr = null;
    private $pass = null;
    private $_conexion = null;
    private $errors = null;

    public function Login(): array
    {
        try {

            global $http;

            $tokenUsr = $http->headers->get("Authorization");

            $data = $this->decodeJWT($tokenUsr);

            // $this->userMail = $data['upn'];
            $this->userMail = $data['preferred_username'];

            # Formato de email
            if (!Helper\Strings::is_email($this->userMail)) {
                throw new ModelsException('El email no tiene un formato válido.');
            }

            $_user = explode('@', $this->userMail);
            $this->usr = strtolower($_user[0]);

            $this->userData = array(
                'user' => $this->usr,
                'email' => $this->userMail,
                'role' => 1,
                'profile' => [
                    'ADM_USUARIOS_METROPLUS',
                    'ADMISIONES_METROPLUS',
                    'EMERGENCIA_METROPLUS',
                    'FARMACIA_METROPLUS',
                    'IMAGEN_METROPLUS',
                    'LABORATORIO_METROPLUS',
                    'HOSPITALIZACION_METROPLUS',
                    'TR_METROPLUS',
                    'NEURO_METROPLUS',
                    'BCO_SANGRE_METROPLUS',
                    'ENDOSCOPIA_METROPLUS',
                    'CONTA_METROPLUS',
                    'TF_METROPLUS',
                    'CARDIO_METROPLUS',
                ],
            );

            # GENERAR LA CLAVE KEY Y JWT
            $auth = new Model\AuthJWT;
            $this->tokenUsr = $auth->generateKeyMetroplus($this->userData);

            return array(
                'status' => true,
                'data' => [
                    'user' => $this->userData,
                    'jwt' => $this->tokenUsr,
                ],
                'message' => 'Acceso exitoso.',
            );

        } catch (ModelsException $e) {

            $error = array(
                'status' => false,
                'data' => $data,
                'message' => $e->getMessage(),
            );

            return $error;

        }
    }

    public function decodeJWT($token)
    {

        $claims_arr = array();

        if ($token !== null) {
            $token_arr = explode('.', $token);
            $claims_enc = $token_arr[1];
            $claims_arr = json_decode($this->base64_url_decode($claims_enc), true);
        }

        return $claims_arr;

    }

    private function base64_url_decode($arg)
    {
        $res = $arg;
        $res = str_replace('-', '+', $res);
        $res = str_replace('_', '/', $res);
        switch (strlen($res) % 4) {
            case 0:
                break;
            case 2:
                $res .= "==";
                break;
            case 3:
                $res .= "=";
                break;
            default:
                break;
        }
        $res = base64_decode($res);
        return $res;
    }

/**
 * __construct()
 */
    public function __construct(IRouter $router = null)
    {
        parent::__construct($router);
    }
}
