package diverter

import (
	"github.com/jamesits/go-windivert/pkg/ffi"
)

func (d *Diverter) SetParam(param ffi.Param, value uint64) (err error) {
	d.critical.Lock()
	defer d.critical.Unlock()

	d.params[param] = value

	if d.started {
		return d.l.SetParam(d.handle, param, value)
	}

	return nil
}

func (d *Diverter) GetParam(param ffi.Param) (value uint64, err error) {
	return d.l.GetParam(d.handle, param)
}
