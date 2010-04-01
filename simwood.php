<?php

/**
 * Simwood API class
 *
 * Copyright (c) 2010 Ca-Phun Ung <caphun at yelotofu dot com>
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * @version 1
 */

class simwood {

	var $options = array();
	var $request = array();
	var $response = array();
	
	// constructor
	function __construct($options = null) {
		
		$this->options = array_merge(array(
			'api_url' => "http://ws.simwood.com/REST.php",
			'threshold' => 60,
			'user' => null,
			'password' => null,
			'output' => 'xml',
		), $options);
		
		return $this;
	}
	
	function get($mode, $options = null) {
		// build request queque
		$this->request[] = array('url' => "{$this->options['api_url']}?mode={$mode}", 'params' => $options);
		// return self
		return $this;
	}
	
	// executes all requests and spits out the result in a concatinated object literal
	function run() {
		
		// TODO: authenticate first
		// get token from session
		$token = $this->get_auth_token();
		
		if ($token) {
			// loop through queque to execute each request
			foreach ($this->request as $request) {
				$this->request(
					$request['url'], 
					array_merge(
						$request['params'], 
						array(
							'token' => $token,
							'output' => $this->options['output'],
						)
					)
				);
			}
			
			// write response to output
			$output = $this->response;
		} else {
			$output = array(
				'ERROR': 'Could not authenticate you',
			);
		}
		
		unset($this->request); // clear request array
		unset($this->response); // clear response array
		
		// output results
		return $output;
	}
	
	// authentication
	function get_auth_token() {
		if (!isset($_SESSION['token'])) {
			// get client ip
			$ip = $this->request("{$this->options['api_url']}?mode=MYIP", array('output'=> 'json',));

			// get time
			$timestamp = $this->request("{$this->options['api_url']}?mode=TIME", array('output'=> 'json',));

			$clientip = json_decode($ip)->results->ip;
			$expiry = json_decode($timestamp)->results->timestamp + $this->options['threshold']; // expiry = time + 60 seconds

			$key=htmlspecialchars(sha1($clientip.$expiry.$this->options['password']));

			// authenticate
			$response = $this->request("{$this->options['api_url']}?mode=AUTH", array(
			  'user'=> $this->options['user'],
			  'expiry' => $expiry,
			  'key' => $key,
			  'output'=> 'json',
			));

			// TODO: check whether authentication is valid before returning a token
			$token = json_decode($response)->results->token;

			// save token to session
			$_SESSION['token'] = $token;
		} else {
			$token = $_SESSION['token'];
		}
		
		// return auth token
		return $token;
	}
	
	// revoke authentication token
	function revoke_auth_token() {
		// get token from session
		$token = $this->get_auth_token();
		
		// get client ip
		$ip = $this->request("{$this->options['api_url']}?mode=MYIP", array('output'=> 'json',));
		$clientip = json_decode($ip)->results->ip;
		
		// revoke token
		$response = $this->request("{$this->options['api_url']}?mode=DEAUTH", array(
		  'user' => $this->options['user'],
		  'token' => $token,
		  'key' => htmlspecialchars(sha1($clientip.$token.$this->options['password'])),
		  'output' => 'json',
		));
		
		// write response into response array
		$this->response['DEAUTH'] = $response;
		
		return $this;
	}
	
	// curl request
	function request($url, $options = null) {
		$ch = curl_init($url);
		curl_setopt ($ch, CURLOPT_POST, 1);
		if ($options != null) {
			curl_setopt ($ch, CURLOPT_POSTFIELDS, $options); 
		}
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$result = curl_exec ($ch);
		//$info = curl_getinfo($ch);
		//$result['http_code'];
		curl_close ($ch);
		
		// get mode
		$mode = 'MYIP'; // TODO: get mode from $url
		
		// write response into response array
		$this->response[$mode] = $result;
		
		// return self
		return $this;
	}
	
}