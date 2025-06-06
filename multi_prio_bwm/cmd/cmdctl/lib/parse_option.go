package lib

import (
	"fmt"
	"oncn-bwm/cmd/daemon/common"
	"strconv"
)

func ConvertConfig(priority string, reqbandwidth string, limitbandwidth string) (*common.QosConfig, error) {
	config := &common.QosConfig{}
	//var err error
	if priority == "" || reqbandwidth == "" || limitbandwidth == "" {
		return nil, fmt.Errorf("option cannot be nil")
	}

	pri, err := strconv.Atoi(priority)
	if err != nil {
		return nil, fmt.Errorf("Invalid value, priority: %s must be an integer", priority)
	}

	reqBw, err := strconv.Atoi(reqbandwidth)
	if err != nil {
		return nil, fmt.Errorf("Invalid value, limit bandwidth: %s must be an integer", reqbandwidth)
	}

	limitBw, err := strconv.Atoi(limitbandwidth)
	if err != nil {
		return nil, fmt.Errorf("Invalid value, limit bandwidth: %s must be an integer", limitbandwidth)
	}

	config.Priority = uint32(pri)
	config.BandWidthRequestM = uint64(reqBw)
	config.BandWidthLimitM = uint64(limitBw)

	if pri > 2 || pri < 0 {
		return nil, fmt.Errorf("priority value: %d is invalid, must be set to 0-2 integer", pri)
	}
	return config, nil
}
