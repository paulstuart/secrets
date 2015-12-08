package secrets

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	gcfg "gopkg.in/gcfg.v1"
)

type Creds struct {
	Username, Password string
}

type Remote struct {
	Remote map[string]*Creds
}

func (config Remote) Copy() (dupe Remote) {
	dupe.Remote = make(map[string]*Creds)
	for k, v := range config.Remote {
		dupe.Remote[k] = &Creds{v.Username, v.Password}
	}
	return
}

func (config Remote) Dump() {
	for k, v := range config.Remote {
		fmt.Printf("%s - %s/%s\n", k, v.Username, v.Password)
	}
}

func (config Remote) Private() {
	for k := range config.Remote {
		config.Remote[k].Username, _ = EncryptString(config.Remote[k].Username)
		config.Remote[k].Password, _ = EncryptString(config.Remote[k].Password)
	}
}

func (config Remote) Public() {
	for k := range config.Remote {
		config.Remote[k].Username, _ = DecryptString(config.Remote[k].Username)
		config.Remote[k].Password, _ = DecryptString(config.Remote[k].Password)
	}
}

func (config Remote) Save(filename string) {
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0664)
	if err != nil {
		log.Print("Can't open file:" + filename + " -- " + err.Error())
		return
	}
	defer file.Close()
	for k, v := range config.Remote {
		fmt.Fprintf(file, "[remote \"%s\"]\n", k)
		fmt.Fprintf(file, "username = %s\n", v.Username)
		fmt.Fprintf(file, "password = %s\n", v.Password)
		fmt.Fprintln(file)
	}
}

func ShowSalt() {
	fmt.Println("salt:", salty)
}

func ConfigLoad(filename string) (config Remote, err error) {
	err = gcfg.ReadFileInto(&config, filename)
	return
}

func ConfigLoadSecret(filename, keyfile string) (config Remote) {
	if err := gcfg.ReadFileInto(&config, filename); err != nil {
		log.Fatal(err.Error())
	}
	if keydata, err := ioutil.ReadFile(keyfile); err != nil {
		log.Fatal(err.Error())
	} else {
		SetKey(string(keydata))
		config.Public()
	}
	return
}

func ConfigCompare(this, that Remote) bool {
	for k, remote := range this.Remote {
		other, ok := that.Remote[k]
		switch {
		case !ok:
			return false
		case remote.Username != other.Username:
			return false
		case remote.Password != other.Password:
			return false
		}
	}
	return true
}
