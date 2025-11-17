// Copyright 2024 New Vector Ltd.
// Copyright 2017 Vector Creations Ltd
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

package routing

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "strings"

    "github.com/element-hq/dendrite/clientapi/auth"
    "github.com/element-hq/dendrite/clientapi/auth/authtypes"
    "github.com/element-hq/dendrite/clientapi/userutil"
    "github.com/element-hq/dendrite/setup/config"
    userapi "github.com/element-hq/dendrite/userapi/api"
    "github.com/matrix-org/gomatrixserverlib/spec"
    "github.com/matrix-org/util"
)

type loginResponse struct {
    UserID      string `json:"user_id"`
    AccessToken string `json:"access_token"`
    DeviceID    string `json:"device_id"`
}

type flows struct {
    Flows []flow `json:"flows"`
}

type flow struct {
    Type string `json:"type"`
}

// ================================
//          LOGIN HANDLER
// ================================
func Login(
    req *http.Request, userAPI userapi.ClientUserAPI,
    cfg *config.ClientAPI,
) util.JSONResponse {

    // ============================================
    // GET /_matrix/client/v3/login
    // ============================================
    if req.Method == http.MethodGet {
        loginFlows := []flow{{Type: authtypes.LoginTypePassword}}
        if len(cfg.Derived.ApplicationServices) > 0 {
            loginFlows = append(loginFlows, flow{Type: authtypes.LoginTypeApplicationService})
        }
        return util.JSONResponse{
            Code: http.StatusOK,
            JSON: flows{Flows: loginFlows},
        }
    }

    // ============================================
    // POST /_matrix/client/v3/login
    // ============================================
    if req.Method == http.MethodPost {

        // -----------------------------------------
        // STEP 1 — Parse input (Matrix-compliant)
        // -----------------------------------------
        type matrixLoginRequest struct {
            Type     string `json:"type"`
            Password string `json:"password"`
            Identifier struct {
                Type string `json:"type"`
                User string `json:"user"`
            } `json:"identifier"`
            Username string `json:"username"`
        }

        var lr matrixLoginRequest
        if err := json.NewDecoder(req.Body).Decode(&lr); err != nil {
            return util.JSONResponse{
                Code: http.StatusBadRequest,
                JSON: spec.BadJSON("Malformed JSON: " + err.Error()),
            }
        }

        // Extract username
        username := lr.Username
        if username == "" && lr.Identifier.Type == "m.id.user" {
            username = lr.Identifier.User
        }

        if username == "" || lr.Password == "" {
            return util.JSONResponse{
                Code: http.StatusBadRequest,
                JSON: spec.BadJSON("username and password are required"),
            }
        }

        // -----------------------------------------
        // STEP 2 — External authentication
        // -----------------------------------------
        payload, _ := json.Marshal(map[string]string{
            "username": username,
            "password": lr.Password,
        })

        extReq, err := http.NewRequest(
            "POST",
            "http://localhost:8000/api/core/v1/auth/login",
            bytes.NewBuffer(payload),
        )
        if err != nil {
            return util.JSONResponse{
                Code: http.StatusInternalServerError,
                JSON: spec.InternalServerError{},
            }
        }

        extReq.Header.Set("Content-Type", "application/json")
        client := &http.Client{}
        resp, err := client.Do(extReq)
        if err != nil {
            return util.JSONResponse{
                Code: http.StatusInternalServerError,
                JSON: spec.InternalServerError{},
            }
        }
        defer resp.Body.Close()

        if resp.StatusCode != http.StatusOK {
            return util.JSONResponse{
                Code: http.StatusForbidden,
                JSON: spec.Forbidden("Invalid credentials"),
            }
        }

        // -----------------------------------------
        // STEP 3 — Convert username → Matrix localpart
        // -----------------------------------------
        localpart, serverName, err := userutil.ParseUsernameParam(username, cfg.Matrix)
        if err != nil {
            return util.JSONResponse{
                Code: http.StatusBadRequest,
                JSON: spec.BadJSON("Invalid username: " + err.Error()),
            }
        }

        // -----------------------------------------
        // STEP 4 — Create account if missing
        // -----------------------------------------
        var accRes userapi.PerformAccountCreationResponse
        err = userAPI.PerformAccountCreation(
            req.Context(),
            &userapi.PerformAccountCreationRequest{
                Localpart:  localpart,
                ServerName: serverName,
            },
            &accRes,
        )

        if err != nil && !strings.Contains(err.Error(), "exists") {
            return util.JSONResponse{
                Code: http.StatusInternalServerError,
                JSON: spec.InternalServerError{},
            }
        }

        // -----------------------------------------
        // STEP 5 — Generate access token
        // -----------------------------------------
        token, err := auth.GenerateAccessToken()
        if err != nil {
            util.GetLogger(req.Context()).WithError(err).Error("auth.GenerateAccessToken failed")
            return util.JSONResponse{
                Code: http.StatusInternalServerError,
                JSON: spec.InternalServerError{},
            }
        }

        // -----------------------------------------
        // STEP 6 — Create Matrix device
        // -----------------------------------------
        var devRes userapi.PerformDeviceCreationResponse
        err = userAPI.PerformDeviceCreation(
            req.Context(),
            &userapi.PerformDeviceCreationRequest{
                DeviceDisplayName: nil,
                DeviceID:          nil,
                AccessToken:       token,
                Localpart:         localpart,
                ServerName:        serverName,
                IPAddr:            req.RemoteAddr,
                UserAgent:         req.UserAgent(),
            },
            &devRes,
        )
        if err != nil {
            return util.JSONResponse{
                Code: http.StatusInternalServerError,
                JSON: spec.Unknown("failed to create device: " + err.Error()),
            }
        }

        // -----------------------------------------
        // STEP 7 — Success
        // -----------------------------------------
        return util.JSONResponse{
            Code: http.StatusOK,
            JSON: loginResponse{
                UserID:      devRes.Device.UserID,
                AccessToken: devRes.Device.AccessToken,
                DeviceID:    devRes.Device.ID,
            },
        }
    }

    // invalid method
    return util.JSONResponse{
        Code: http.StatusMethodNotAllowed,
        JSON: spec.NotFound("Bad method"),
    }
}

// ======================================================================
// ORIGINAL completeAuth (unchanged)
// ======================================================================
func completeAuth(
    ctx context.Context, cfg *config.Global, userAPI userapi.ClientUserAPI, login *auth.Login,
    ipAddr, userAgent string,
) util.JSONResponse {
    token, err := auth.GenerateAccessToken()
    if err != nil {
        util.GetLogger(ctx).WithError(err).Error("auth.GenerateAccessToken failed")
        return util.JSONResponse{
            Code: http.StatusInternalServerError,
            JSON: spec.InternalServerError{},
        }
    }

    localpart, serverName, err := userutil.ParseUsernameParam(login.Username(), cfg)
    if err != nil {
        util.GetLogger(ctx).WithError(err).Error("auth.ParseUsernameParam failed")
        return util.JSONResponse{
            Code: http.StatusInternalServerError,
            JSON: spec.InternalServerError{},
        }
    }

    var res userapi.PerformDeviceCreationResponse
    err = userAPI.PerformDeviceCreation(
        ctx,
        &userapi.PerformDeviceCreationRequest{
            DeviceDisplayName: login.InitialDisplayName,
            DeviceID:          login.DeviceID,
            AccessToken:       token,
            Localpart:         localpart,
            ServerName:        serverName,
            IPAddr:            ipAddr,
            UserAgent:         userAgent,
        },
        &res,
    )
    if err != nil {
        return util.JSONResponse{
            Code: http.StatusInternalServerError,
            JSON: spec.Unknown("failed to create device: " + err.Error()),
        }
    }

    return util.JSONResponse{
        Code: http.StatusOK,
        JSON: loginResponse{
            UserID:      res.Device.UserID,
            AccessToken: res.Device.AccessToken,
            DeviceID:    res.Device.ID,
        },
    }
}