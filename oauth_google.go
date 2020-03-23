package oauth_google

import (
    "fmt" // пакет для форматированного ввода вывода
    "net/http"
    "github.com/a1div0/oauth"
    "net/url"
    "io/ioutil"
    "encoding/json"
    "time"
)

// Manual
// https://developers.google.com/identity/protocols/OAuth2WebServer

type OAuthGoogle struct {
    ClientId string
    ClientSecret string
    token string
    token_dt_start time.Time
    token_dt_end time.Time
    refresh_token string
    redirect_uri string
}

func (s *OAuthGoogle) ServiceName() (string) {
    return "google"
}

func (s *OAuthGoogle) LoginURL(verification_code_callback_url string, state string) (string) {

    s.redirect_uri = verification_code_callback_url

    data := url.Values{}
    data.Set("client_id"    , s.ClientId)
    data.Set("redirect_uri" , verification_code_callback_url)
    data.Set("scope"        , "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile")
    data.Set("access_type"  , "offline")
    data.Set("state"        , state)
    data.Set("response_type", "code")

    return "https://accounts.google.com/o/oauth2/v2/auth?" + data.Encode()
}

func (s *OAuthGoogle) OnRecieveVerificationCode(code string, u *oauth.UserData) (error) {

    // Посылаем запрос токена и код подтверждения
    err := s.code_to_token(code)
    if err != nil {
		return err
	}
    err = s.token_to_userdata(u)
    if err != nil {
		return err
	}
    return nil
}

func (s *OAuthGoogle) code_to_token(code string) (error) {

    formData := url.Values{
        "code": {code},
        "client_id": {s.ClientId},
        "client_secret": {s.ClientSecret},
        "redirect_uri": {s.redirect_uri},
        "grant_type": {"authorization_code"},
	}

    resp, err := http.PostForm("https://oauth2.googleapis.com/token", formData)
	if err != nil {
		return err
    }
    defer resp.Body.Close()

    type GoTokenAnswerStruct struct {
        Token_type string       `json:"token_type"`
        Access_token string     `json:"access_token"`
        Expires_in int64        `json:"expires_in"`
        Refresh_token string    `json:"refresh_token"`
        Error string            `json:"error"`
        ErrorDescription string `json:"error_description"`
    }
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return err
    }

    var GoTokenAnswer GoTokenAnswerStruct

    err = json.Unmarshal(body, &GoTokenAnswer)
    if err != nil {
		return err
    }
    if (GoTokenAnswer.Error != "") {
        return fmt.Errorf("Error - %s: %s", GoTokenAnswer.Error, GoTokenAnswer.ErrorDescription)
    }

    sec_left := time.Second * time.Duration(GoTokenAnswer.Expires_in)

    s.token = GoTokenAnswer.Access_token
    s.token_dt_start = time.Now()
    s.token_dt_end = s.token_dt_start.Add(sec_left)
    s.refresh_token = GoTokenAnswer.Refresh_token

    return nil
}

func (s *OAuthGoogle) token_to_userdata(u *oauth.UserData) (error) {

    req, err := http.NewRequest("GET", "https://www.googleapis.com/oauth2/v1/userinfo?alt=json", nil)
	if err != nil {
		return err
	}
	// Получаем и устанавливаем тип контента
	req.Header.Set("Authorization", "Bearer " + s.token)

	// Отправляем запрос
	client := &http.Client{}
	resp, err := client.Do(req)
    defer resp.Body.Close()
	if err != nil {
		return err
	}

    type GoUserAnswerStruct struct {
        Id string `json:"id"`
        Email string `json:"email"`
        VerifiedEmail bool `json:"verified_email"`
        Name string `json:"name"`
        PictureUrl string `json:"picture"`
    }

    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
		return err
    }

    var GoUserAnswer GoUserAnswerStruct
    err = json.Unmarshal(body, &GoUserAnswer)
    if err != nil {
		return err
    }

    u.ExtId = GoUserAnswer.Id
    u.Name = GoUserAnswer.Name
    u.Email = GoUserAnswer.Email

    return nil
}
