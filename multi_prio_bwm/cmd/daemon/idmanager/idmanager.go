package idmanager

import (
	"fmt"
	"oncn-bwm/cmd/daemon/common"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	MinFlowID uint16 = 100
	MaxFlowID uint16 = 999
	MinPodID  uint16 = 1000
	MaxPodID  uint16 = 5999
)

// podid--containerid--podinfo
type IDManager struct {
	podIdMap       map[uint16]string
	containerIdMap map[string]common.PodInfo
	flowIdMap      map[uint16]string
	processIdMap   map[string]common.ProcessInfo
	mutex          sync.Mutex
	maxPodID       uint16
	minPodID       uint16
	maxFlowID      uint16
	minFlowID      uint16
}

func NewPodIDManager() *IDManager {
	return &IDManager{
		podIdMap:       make(map[uint16]string),
		containerIdMap: make(map[string]common.PodInfo),
		flowIdMap:      make(map[uint16]string),
		processIdMap:   make(map[string]common.ProcessInfo),
		maxPodID:       MaxPodID,
		minPodID:       MinPodID,
		maxFlowID:      MaxFlowID,
		minFlowID:      MinFlowID,
	}
}

func (idAllocator *IDManager) AllocatePodId(podInfo *common.PodInfo) (uint16, error) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	//是否已经分配过
	if Info, ok := idAllocator.containerIdMap[podInfo.ContainerId]; ok {
		log.Debugf("podinfo [%+v] has have localid %d", podInfo, Info.LocalId)
		podInfo.LocalId = Info.LocalId
		return Info.LocalId, nil
	}
	//重新分配
	for id := idAllocator.minPodID; id <= idAllocator.maxPodID; id++ {
		if _, ok := idAllocator.podIdMap[id]; !ok {
			idAllocator.podIdMap[id] = podInfo.ContainerId
			podInfo.LocalId = id
			idAllocator.containerIdMap[podInfo.ContainerId] = *podInfo
			log.Infof("alloc podinfo [%+v] localid %d", podInfo, id)
			return id, nil
		}
	}
	return 0, fmt.Errorf("no available local id")
}

func (idAllocator *IDManager) ReleaseByPodId(podId uint16) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if containerId, ok := idAllocator.podIdMap[podId]; ok {
		log.Infof("release podinfo [%+v] localid %d", idAllocator.containerIdMap[containerId], podId)
		delete(idAllocator.containerIdMap, containerId)
		delete(idAllocator.podIdMap, podId)
	}
}

func (idAllocator *IDManager) ReleasePodIdByContainerId(containerId string) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if podInfo, ok := idAllocator.containerIdMap[containerId]; ok {
		log.Infof("release podinfo [%+v] localid %d", podInfo, podInfo.LocalId)
		delete(idAllocator.podIdMap, podInfo.LocalId)
		delete(idAllocator.containerIdMap, containerId)
	}
}

func (idAllocator *IDManager) InsertPodInfo(containerId string, podInfo *common.PodInfo) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	idAllocator.podIdMap[podInfo.LocalId] = containerId
	idAllocator.containerIdMap[containerId] = *podInfo
	log.Infof("insert podinfo [%+v] localid %d", podInfo, podInfo.LocalId)
}

func (idAllocator *IDManager) LookupPodInfoByContainId(containerId string) (*common.PodInfo, error) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if podInfo, ok := idAllocator.containerIdMap[containerId]; ok {
		return &podInfo, nil
	} else {
		return nil, fmt.Errorf("no podinfo for containerid %s", containerId)
	}
}

func (idAllocator *IDManager) LookupPodInfoByLocalId(localId uint16) (*common.PodInfo, error) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if containerId, ok := idAllocator.podIdMap[localId]; ok {
		if podInfo, ok := idAllocator.containerIdMap[containerId]; ok {
			return &podInfo, nil
		} else {
			return nil, fmt.Errorf("no podinfo for containerid %s", containerId)
		}
	} else {
		return nil, fmt.Errorf("no podinfo for localid %d", localId)
	}
}

func (idAllocator *IDManager) ListPodInfo() []*common.PodInfo {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	var podInfoSlice []*common.PodInfo
	for _, info := range idAllocator.containerIdMap {
		copyOfInfo := info
		podInfoSlice = append(podInfoSlice, &copyOfInfo)
	}
	return podInfoSlice
}

func (idAllocator *IDManager) AllocateProcessId(processInfo *common.ProcessInfo) (uint16, error) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	//是否已经分配过
	if Info, ok := idAllocator.processIdMap[processInfo.ProcessId]; ok {
		log.Debugf("processinfo [%+v] has have localid %d", processInfo, Info.LocalId)
		processInfo.LocalId = Info.LocalId
		return Info.LocalId, nil
	}
	//重新分配
	for id := idAllocator.minFlowID; id <= idAllocator.maxFlowID; id++ {
		if _, ok := idAllocator.flowIdMap[id]; !ok {
			idAllocator.flowIdMap[id] = processInfo.ProcessId
			processInfo.LocalId = id
			idAllocator.processIdMap[processInfo.ProcessId] = *processInfo
			log.Infof("alloc processinfo [%+v] localid %d", processInfo, id)
			return id, nil
		}
	}
	return 0, fmt.Errorf("no available local id")
}

func (idAllocator *IDManager) ReleaseProcessInfo(processId string) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if processInfo, ok := idAllocator.processIdMap[processId]; ok {
		log.Infof("release processinfo [%+v] localid %d", processInfo, processInfo.LocalId)
		delete(idAllocator.flowIdMap, processInfo.LocalId)
		delete(idAllocator.processIdMap, processId)
	}
}

func (idAllocator *IDManager) InsertProcessInfo(processId string, processInfo *common.ProcessInfo) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	idAllocator.podIdMap[processInfo.LocalId] = processId
	idAllocator.processIdMap[processId] = *processInfo
	log.Infof("insert processinfo [%+v] localid %d", processInfo, processInfo.LocalId)
}

func (idAllocator *IDManager) LookupProcessInfo(processId string) (*common.ProcessInfo, error) {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	if processInfo, ok := idAllocator.processIdMap[processId]; ok {
		return &processInfo, nil
	} else {
		return nil, fmt.Errorf("no processinfo for processid %s", processId)
	}
}

func (idAllocator *IDManager) ListProcessInfo() []*common.ProcessInfo {
	idAllocator.mutex.Lock()
	defer idAllocator.mutex.Unlock()
	var processInfoSlice []*common.ProcessInfo
	for _, info := range idAllocator.processIdMap {
		copyOfInfo := info
		processInfoSlice = append(processInfoSlice, &copyOfInfo)
	}
	return processInfoSlice
}
