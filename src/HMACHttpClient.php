<?php
namespace RB\Sphinx\Hmac\Zend\Client;

use Zend\Http\Client;
use Zend\Http\Request;
use Zend\Http\Response;
use Zend\Http\Exception\RuntimeException;
use RB\Sphinx\Hmac\HMAC;
use RB\Sphinx\Hmac\HMACSession;

class HMACHttpClient extends Client
{

    const HMAC_HEADER = 0;
    const HMAC_URI = 1;
    const VERSION = 1;
    const HEADER_NAME = 'HMAC-Authentication';
    const HEADER_NAME_SESSION = 'HMAC-Authentication-Session';
    const URI_PARAM_NAME = "hmacauthentication";

    protected $hmacMode = self::HMAC_HEADER;

    /**
     * 
     * @var HMAC
     */
    protected $hmac = null;

    /**
     * Contador de mensagens enviadas
     * @var int
     */
    protected $hmacContador = 0;

    /**
     * Indicar se sessão já foi iniciada
     * @var bool
     */
    protected $hmacSession = false;

    /**
     * Indicar se URI já foi autenticada
     * @var bool
     */
    protected $hmacSignedUri = false;
    protected $hmacSignedUriString = null;

    /**
     * Iniciar sessão HMAC
     * @param Request $request
     * @throws RuntimeException
     */
    protected function _startSession(Request $request)
    {
        /**
         * Clonar requisição inicial para aproveitar configurações
         */
        $sessionRequest = clone $request;

        /**
         * Início de sessão com header adicional (sem BODY)
         */
        $sessionRequest->getHeaders()->addHeaderLine(self::HEADER_NAME_SESSION, 'Start');
        $sessionRequest->setContent('');

        /**
         * Assinatura de início de sessão (igual assinatura sem sessão)
         */
        $this->_sign($sessionRequest);

        /**
         * Requisitar início de sessão
         */
        $response = parent::send($sessionRequest);

        /**
         * Recuperar header com assinatura HMAC
         */
        $header = $response->getHeaders()->get(self::HEADER_NAME);

        if ($header === false)
            throw new RuntimeException('HMAC não está presente na resposta');

        $header = $header->getFieldValue();

        $headerData = explode(':', $header);
        if (count($headerData) != 3)
            throw new RuntimeException('HMAC da resposta é inválido (header incorreto)');

        $versao = $headerData[0];
        $nonce2 = $headerData[1];
        $assinatura = $headerData[2];

        /**
         * Verificar versão do protocolo
         */
        if ($versao != self::VERSION)
            throw new RuntimeException('HMAC da resposta é inválido (versão incorreta)');

        /**
         * Informar Nonce2 enviado pelo servidor
         */
        $this->hmac->setNonce2Value($nonce2);

        /**
         * Verificar assinatura do NONCE2 enviado pelo servidor
         */
        $this->hmac->validate($nonce2, $assinatura, HMACSession::SESSION_RESPONSE);

        /**
         * Indicar início da sessão após validar resposta
         */
        $this->hmac->startSession();
        $this->hmacSession = true;
    }

    /**
     * Assinar requisição (sem sessão)
     * @param Request $request
     * @throws RuntimeException
     */
    protected function _sign(Request $request)
    {
        if ($this->hmacContador > 0)
            throw new RuntimeException('HMAC sem sessão só pode enviar uma mensagem');

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        $assinarDados = $request->getMethod()                     // método
            . $request->getUriString()                // URI
            . $request->getContent();                 // content

        /**
         * Assinatura HMAC
         */
        $assinaturaHmac = $this->hmac->getHmac($assinarDados, HMACSession::SESSION_REQUEST);

        /**
         * Header de autenticação (protocolo versão 1)
         */
        $headerAuth = self::VERSION    // versão do protocolo
            . ':' . $this->hmac->getKeyId()         // ID da chave/aplicação/cliente
            . ':' . $this->hmac->getNonceValue()    // nonce
            . ':' . $assinaturaHmac;                // HMAC Hash

        $request->getHeaders()->addHeaderLine(self::HEADER_NAME, $headerAuth);
    }

    /**
     * Assinar URI (sem sessão)
     * @param Request $request
     * @throws RuntimeException
     */
    protected function _signUri(Request $request)
    {
        if ($this->hmacContador > 0)
            throw new RuntimeException('HMAC sem sessão só pode enviar uma mensagem');

        /**
         * Gera URI assinada
         */
        $this->getSignedUri($request);
    }

    /**
     * Retornar URI com autenticação HMAC (HMACUriAdapter)
     * @param Request $request
     * @throws RuntimeException
     * @return string
     */
    public function getSignedUri(Request $request = null)
    {

        if ($this->hmacSignedUri)
            return $this->hmacSignedUriString;

        if ($this->hmac === null)
            throw new RuntimeException('HMAC é necessário para a requisição');

        if ($request === null)
            $request = $this->getRequest();

        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        $assinarDados = $request->getUriString()
            . ( ($request->getQuery()->count() > 0) ? ( strpos($request->getUriString(), '?') !== false ? '&' : '?' ) : NULL )
            . $request->getQuery()->toString();   // URI

        /**
         * Assinatura HMAC
         */
        $assinaturaHmac = $this->hmac->getHmac($assinarDados, HMACSession::SESSION_REQUEST);

        /**
         * Parâmetro de autenticação (protocolo versão 1)
         */
        $authParam = self::VERSION    // versão do protocolo
            . ':' . $this->hmac->getKeyId()         // ID da chave/aplicação/cliente
            . ':' . $this->hmac->getNonceValue()    // nonce
            . ':' . $assinaturaHmac;                // HMAC Hash

        /**
         * Acrescentar parâmetro HMAC na URI original
         */
        $this->hmacSignedUri = true;
        $request->getQuery()->offsetSet(self::URI_PARAM_NAME, $authParam);

        $uri = $request->getUriString()
            . (strpos($request->getUriString(), '?') === false ? ($request->getQuery()->count() > 0 ? '?' : NULL) : '&')
            . $request->getQuery()->toString();   // URI

        $this->hmacSignedUriString = $uri;
        return $uri;
    }

    /**
     * Assinar requisição (com sessão)
     * @param Request $request
     * @throws RuntimeException
     */
    protected function _signSession(Request $request)
    {
        /**
         * Dados a assinar (versão 1 do protocolo)
         */
        $assinarDados = $request->getMethod()                     // método
            . $request->getUriString()                // URI
            . $request->getContent();                 // content

        /**
         * Assinatura HMAC
         */
        $assinaturaHmac = $this->hmac->getHmac($assinarDados, HMACSession::SESSION_MESSAGE);

        /**
         * Header de autenticação (protocolo versão 1)
         */
        $headerAuth = self::VERSION    // versão do protocolo
            . ':' . $assinaturaHmac;                // HMAC Hash

        $request->getHeaders()->addHeaderLine(self::HEADER_NAME, $headerAuth);
    }

    /**
     * Verificar assinatura da resposta do servidor (sem sessão)
     * @param Response $response
     * @throws RuntimeException
     */
    protected function _verify(Response $response)
    {
        /**
         * Recuperar header com assinatura HMAC
         */
        $header = $response->getHeaders()->get(self::HEADER_NAME);
        
        if($this->getStream()){
            return;
        }

        if ($header === false)
            throw new RuntimeException('HMAC não está presente na resposta');

        $header = $header->getFieldValue();

        $headerData = explode(':', $header);
        if (count($headerData) != 2)
            throw new RuntimeException('HMAC da resposta é inválido (header incorreto)');

        $versao = $headerData[0];
        $assinatura = $headerData[1];

        /**
         * Verificar versão do protocolo
         */
        if ($versao != self::VERSION)
            throw new RuntimeException('HMAC da resposta é inválido (versão incorreta)');

        $body = $response->getBody();


        /**
         * Verificar assinatura
         */
        $this->hmac->validate($body, $assinatura, HMACSession::SESSION_MESSAGE);
    }

    /**
     * (non-PHPdoc)
     * 
     * Acrescenta HEADER para autenticação HMAC antes de enviar a requisição.
     * Verificar HEADER HMAC na resposta antes de devolver a resposta.
     * 
     * @see \Zend\Http\Client::send()
     */
    public function send(Request $request = null)
    {

        if ($this->hmac === null)
            throw new RuntimeException('HMAC é necessário para a requisição');

        if ($request === null)
            $request = $this->getRequest();

        /**
         * Verificar se é com ou sem sessão
         */
        if ($this->hmac instanceof HMACSession) {

            /**
             * Iniciar sessão
             */
            if (!$this->hmacSession)
                $this->_startSession($request);

            /**
             * Assinar requisição
             */
            $this->_signSession($request);
        } else {

            /**
             * Assinar requisição
             */
            switch ($this->hmacMode) {
                case self::HMAC_URI:
                    $this->_signUri($request);
                    break;
                case self::HMAC_HEADER:
                default:
                    $this->_sign($request);
            }
        }

        /**
         * Enviar requisição
         */
        $response = parent::send($request);

        /**
         * Verificar se servidor informou erro de HMAC
         */
        if ($response->getStatusCode() == 401) {
            $detalhes = '';

            try {
                $json = json_decode($response->getBody());
                if ($json === null) {
                    /**
                     * Erro 401 não gerado pelo HMAC no servidor
                     */
                    $detalhes = $response->getBody();
                } else {
                    if (!property_exists($json, 'detail')) {
                        /**
                         * JSON não foi gerado pelo HMAC Server
                         */
                        $detalhes = $response->getBody();
                    } else {
                        $detalhes = $json->detail;

                        /**
                         * Alertar da necessidade de início de sessão para comunicação com URI
                         */
                        if (strcmp($json->detail, 'HMAC Authentication required') == 0) {
                            if ($this->hmac instanceof HMACSession) {
                                $detalhes .= ' (sessão HMAC expirou)';
                            } else {
                                $detalhes .= ' (servidor requer HMAC com sessão)';
                            }
                        } elseif (strcmp($json->detail, '5 - Sessão HMAC não iniciada') == 0) {
                            if ($this->hmac instanceof HMACSession) {
                                $detalhes .= ' (sessão HMAC expirou)';
                            } else {
                                $detalhes .= ' (servidor requer HMAC com sessão)';
                            }
                        }

                        /**
                         * Detalhes adicionais enviados pelo servidor
                         */
                        if (property_exists($json, 'hmac'))
                            $detalhes .= ' [' . $json->hmac . ' v' . $json->version . ']';
                    }
                }
            } catch (Exception $e) {
                
            }

            throw new RuntimeException('Erro HMAC remoto: ' . $detalhes, 401);
        }

        /**
         * Verificar assinatura da resposta, se for resposta de sucesso (2xx)
         */
        if ($response->getStatusCode() >= 200 && $response->getStatusCode() <= 299)
            $this->_verify($response);


        /**
         * Incrementar contador interno após validar resposta
         */
        $this->hmacContador++;
        if ($this->hmac instanceof HMACSession) {
            $this->hmac->nextMessage(); // Incrementar contagem na sessão após validar resposta
        }


        return $response;
    }

    /**
     * 
     * @param HMAC $hmac
     * @return \RB\Sphinx\Hmac\Zend\Client\HMACHttpClient
     */
    public function setHmac(HMAC $hmac)
    {
        $this->hmac = $hmac;
        return $this;
    }

    /**
     * 
     * @return \RB\Sphinx\Hmac\HMAC
     */
    public function getHmac()
    {
        return $this->hmac;
    }

    /**
     * 
     * @param int $modo
     * @return \RB\Sphinx\Hmac\Zend\Client\HMACHttpClient
     */
    public function setHmacMode($modo)
    {
        $this->hmacMode = $modo;
        return $this;
    }

    /**
     * 
     * @return int
     */
    public function getHmacMode()
    {
        return $this->hmacMode;
    }
}
