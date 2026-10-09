package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// managementRegions are Kiro's canonical management regions. A profile is
// owned by one of them and ListAvailableProfiles only lists profiles owned by
// the region it is called in, so discovery probes the credential's own region
// first and then the other.
var managementRegions = []string{"us-east-1", "eu-central-1"}

type listProfilesResponse struct {
	Profiles []struct {
		ARN string `json:"arn"`
	} `json:"profiles"`
}

// discoverProfileARN finds the Kiro profile for an OAuth credential. A 403 in
// one region means the profile lives elsewhere, so probing continues; the last
// 403 is returned only when no region lists a profile.
func discoverProfileARN(hostCallbackID string, credential kiroCredential) (string, error) {
	token, errToken := bearerToken(credential)
	if errToken != nil {
		return "", errToken
	}
	var lastErr error
	for _, region := range candidateManagementRegions(apiRegion(credential.Region)) {
		headers := http.Header{
			"Accept":       []string{"application/json"},
			"Content-Type": []string{"application/json"},
		}
		applyAuthHeaders(headers, credential, token)
		var response listProfilesResponse
		errList := postJSON(hostCallbackID, "https://management."+region+".kiro.dev/List-Available-Profiles", headers, []byte("{}"), &response)
		if errList != nil {
			var statusErr *tokenRefreshError
			if errors.As(errList, &statusErr) && statusErr.status == http.StatusForbidden {
				lastErr = errList
				continue
			}
			return "", errList
		}
		for _, profile := range response.Profiles {
			if regionFromProfileARN(profile.ARN) != "" {
				return profile.ARN, nil
			}
		}
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("no Kiro profile listed in %v", managementRegions)
}

func candidateManagementRegions(primary string) []string {
	regions := []string{primary}
	for _, region := range managementRegions {
		if region != primary {
			regions = append(regions, region)
		}
	}
	return regions
}

// profileListing is exported to tests to build canned responses.
func profileListing(arns ...string) []byte {
	var response listProfilesResponse
	for _, arn := range arns {
		response.Profiles = append(response.Profiles, struct {
			ARN string `json:"arn"`
		}{ARN: arn})
	}
	raw, _ := json.Marshal(response)
	return raw
}
