// *************************************************************************
//
// REFRACTION POINT CONFIDENTIAL
// __________________
//
//  Copyright 2018 Refraction Point Inc.
//  All Rights Reserved.
//
// NOTICE:  All information contained herein is, and remains
// the property of Refraction Point Inc. and its suppliers,
// if any.  The intellectual and technical concepts contained
// herein are proprietary to Refraction Point Inc
// and its suppliers and may be covered by U.S. and Foreign Patents,
// patents in process, and are protected by trade secret or copyright law.
// Dissemination of this information or reproduction of this material
// is strictly forbidden unless prior written permission is obtained
// from Refraction Point Inc.
//

package arl

import (
	"testing"
)

func TestValidation(t *testing.T) {
	if _, err := NewARL("[xxxx,google.com]", 1024, 3); err == nil {
		t.Error("invalid method failed to produce error")
	}

	if _, err := NewARL("[https,google.com,nope,aaa]", 1024, 3); err == nil {
		t.Error("invalid auth failed to produce error")
	}
}

func TestGCS(t *testing.T) {

}

func TestHTTP(t *testing.T) {
	a, err := NewARL("[https,app.limacharlie.io/get/windows/64]", 1024*1024*10, 3)
	if err != nil {
		t.Errorf("failed to creating https ARL: %v", err)
	}
	ch, err := a.Fetch()
	if err != nil {
		t.Errorf("failed fetching https ARL: %v", err)
	}

	contents := []Content{}
	for c := range ch {
		contents = append(contents, c)
	}

	if len(contents) != 1 {
		t.Errorf("unexpected number of files from https ARL: %d", len(contents))
	}

	content := contents[0]
	if content.Error != nil {
		t.Errorf("unexpected error fetching https ARL: %v", content.Error)
	}
	if len(content.Data) < 1024 || len(content.Data) > 1024*1024*20 {
		t.Errorf("unexpected data size from https ARL: %d", len(content.Data))
	}

	a, err = NewARL("[https,google.com/nope]", 1024, 3)
	_, err = a.Fetch()
	if err == nil {
		t.Error("non existent https dest failed to produce error")
	}
}
