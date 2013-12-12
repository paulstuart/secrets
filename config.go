package secrets

import (
	"code.google.com/p/gcfg"
	"fmt"
    "io/ioutil"
	"log"
    "os"
)

type Creds struct {
    Username, Password string
}

type FilerConfig struct {
	Filer map[string]*Creds
}

func (config FilerConfig) Copy() (dupe FilerConfig) {
    dupe.Filer = make(map[string]*Creds)
	for k, v := range config.Filer {
        dupe.Filer[k] = &Creds{v.Username, v.Password}
	}
    return
}

func (config FilerConfig) Dump() {
	for k, v := range config.Filer {
		fmt.Printf("%s - %s/%s\n", k, v.Username, v.Password)
	}
}

func (config FilerConfig) Private() {
	for k := range config.Filer {
        config.Filer[k].Username = encryptString(config.Filer[k].Username)
        config.Filer[k].Password = encryptString(config.Filer[k].Password)
	}
}

func (config FilerConfig) Public() {
	for k := range config.Filer {
        config.Filer[k].Username = decryptString(config.Filer[k].Username)
        config.Filer[k].Password = decryptString(config.Filer[k].Password)
	}
}

func (config FilerConfig) Save(filename string) {
    file, err := os.OpenFile(filename, os.O_CREATE|os.O_RDWR, 0664)
    if err != nil {
        log.Print("Can't open file:" + filename + " -- " + err.Error())
        return
    }
    defer file.Close()
	for k, v := range config.Filer {
		fmt.Fprintf(file, "[filer \"%s\"]\n", k)
		fmt.Fprintf(file, "username = %s\n", v.Username)
		fmt.Fprintf(file, "password = %s\n", v.Password)
		fmt.Fprintln(file)
	}
}

func ShowSalt() {
    fmt.Println("salt:",salty)
}

func ConfigLoad(filename string) (config FilerConfig, err error) {
	err = gcfg.ReadFileInto(&config, filename)
    return
}

func ConfigLoadSecret(filename, keyfile string) (config FilerConfig) {
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

func ConfigCompare(this, that FilerConfig) bool {
	for k, filer := range this.Filer {
        other,ok := that.Filer[k]
        switch {
        case ! ok:
            return false
        case filer.Username != other.Username:
            return false
        case filer.Password != other.Password:
            return false
        }
	}
    return true
}

