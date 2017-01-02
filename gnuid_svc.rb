require 'sinatra'
require 'sinatra/cookies'
require 'json'
require 'base64'
require 'date'
require 'rest_client'
require 'cgi'

enable :sessions

requiredInfo = [ "email", "name" ]

knownUserKeys = Array.new

$knownIdentities = {}
$passwords = {}
$codes = {}
$nonces = {}

def exchange_code_for_token(id_ticket, expected_nonce)
  p "Expected nonce: "+expected_nonce.to_s
  resp = `curl -X POST 'http://local.gnu:7776/idp/token?ticket=#{id_ticket}&expected_nonce=#{expected_nonce}'`
  p resp
  json = JSON.parse(resp)
  p json
  return nil if json.nil? or json.empty?
  token = json["token"]
  return nil if token.nil?
  header_b64 = token.split(".")[0]
  payload_b64 = token.split(".")[1]
  signature = token.split(".")[2]
  plain = Base64.decode64(payload_b64)
  payload = JSON.parse(plain)
  return nil unless expected_nonce == payload["nonce"].to_i
  identity = payload["iss"]
  p payload
  $knownIdentities[identity] = payload
  $codes[identity] = id_ticket
  return identity
end

def is_token_expired (token)
  return true if token.nil?
  identity = $knownIdentities[token["iss"]]
  exp = Time.at(token["exp"] / 1000000)
  if (Time.now > exp)
    # Get new token
    new_token = `gnunet-gns -u #{$codes[identity]}.gnu -p #{token["iss"]} -t ID_TOKEN --raw -T 5000`
    if (new_token.nil? or new_token.empty?)
      $knownIdentities[token["iss"]] = nil
      return true
    end
    new_token = JSON.parse(new_token)
    exp = Time.at(new_token["exp"] / 1000000)
    if (Time.now > exp)
      $knownIdentities[token["iss"]] = nil
      return true
    else
      $knownIdentities[token["iss"]] = new_token
      return false
    end
  else
    # Check if token revoked
    return false
  end
end

get '/logout' do
  if (!session["user"].nil?)
    session["user"] = nil
    redirect to('/login')
  end
  return "Not logged in"
end

def getUser(identity)
  return nil if identity.nil? or $knownIdentities[identity].nil?
  return $knownIdentities[identity]["full_name"] unless $knownIdentities[identity]["full_name"].nil?
  return $knownIdentities[identity]["sub"]
end

get '/' do
  identity = session["user"]

  if (!identity.nil?)
    token = $knownIdentities[identity]
    #if (is_token_expired (token))
    #  # Token is expired
    #  redirect "/login"
    #end
    if (!token.nil?)
      phone = token["phone"]
      #msg = "Welcome back #{$knownIdentities[identity]["sub"]}"
      #msg += "<br/> Your phone number is: #{phone}"
      exp = token["exp"] / 1000000
      #msg += "<br/>Your token will expire at: #{Time.at(exp).to_s}"
      return haml :info, :locals => {
        :user => getUser(identity),
        :title => "Userinfo",
        :subtitle => "Welcome back #{$knownIdentities[identity]["full_name"]}",
        :content => "Your <b>phone</b> number is: #{phone}<br/>Your token will <b>expire at</b>: #{Time.at(exp).to_s}.<br/>Used <b>ticket</b>: #{$codes[identity]}.<br/>Token: #{$knownIdentities[identity]}<br/>"}
    end
  end

  redirect "/login"
end

get "/login" do
  identity = session["user"]
  token = params[:id_token]
  id_ticket = params[:ticket]

  # Identity parameter takes precendence over cookie
  #if (!params[:identity].nil?)
  #  identity = params[:identity]
  #end

  if (!identity.nil?)
    token = $knownIdentities[identity]
    p token
    #if ($passwords[identity].nil?)
    #  # New user -> register
    #  redirect "/register?identity="+identity
    #  return
    #end

    #if (is_token_expired (token))
      # Token is expired
    #  p "Token expired!"
    #end
    
    if (!token.nil?)
      redirect "/"
    end

  end

  if (!id_ticket.nil?)
    identity = exchange_code_for_token(id_ticket, $nonces[session["id"]])
    p "Deleting nonce"
    $nonces[session["id"]] = nil
    if (identity.nil?)
      return "Error!"
    end
    token = $knownIdentities[identity]
    p token
    phone = $knownIdentities[identity]["phone"]
    session["user"] = identity
    if (phone.nil?)
      return "You did not provide a valid phone attribute. Please grant us access to your phone number so we can call you in emergencies!<br/> <a href=http://localhost:8000/index.html#/identities/#{identity}?requested_by=http%3A//localhost%3A4567/&requested_attrs=phone>Grant access</a>"
    end
    #Handle token contents
    redirect "/"
  elsif (identity.nil?)
    nonce = rand(100000)
    session["id"] = rand(100000)
    $nonces[session["id"]] = nonce
    return haml :login, :locals => {
      :user => getUser(nil),
      :title => "Login",
      :nonce => nonce
    }
    #elsif (oauth_code.nil?)
    #  haml :grant, :locals => {:user => getUser(identity), :haml_id => identity, :title => "Information Needed"}
    #elsif (!identity.nil? and !grant_lbl.nil?)
    #  $knownIdentities[identity] = grant_lbl
  end
end


def setCred(attribute, subject_key, expiration)
  response = RestClient.get 'http://127.0.0.1:7776/credential/issue', :params => {:attribute => attribute, :subject_key => subject_key, :expiration => expiration}
  res = JSON.parse(response)
  data = res["data"]
  subject_key = data[0]["attributes"]["credential"]["subject"]
  credential = data[0]["id"]
  attribute = data[0]["id"].split(".").last
  p attribute
  return haml :issue, :locals => {:issueResult => CGI.escape(response), :subject_key => subject_key, :credential => credential, :attribute => attribute}
end


get '/issue' do
  return haml :issue
end

post '/issue' do
  setCred(params[:attribute], params[:subject_key], params[:expiration]) 
end

