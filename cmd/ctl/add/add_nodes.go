/*
Copyright 2020 The KubeSphere Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package add

import (
	kubekeyapiv1alpha2 "github.com/kubesphere/kubekey/apis/kubekey/v1alpha2"
	"github.com/kubesphere/kubekey/cmd/ctl/options"
	"github.com/kubesphere/kubekey/cmd/ctl/util"
	"github.com/kubesphere/kubekey/pkg/common"
	"github.com/kubesphere/kubekey/pkg/pipelines"
	"github.com/spf13/cobra"
)

type AddNodesOptions struct {
	CommonOptions    *options.CommonOptions
	ClusterCfgFile   string
	SkipPullImages   bool
	ContainerManager string
	DownloadCmd      string
	Artifact         string
	InstallPackages  bool

	Kubernetes              string
	RegistryMirrors         string
	MasterHost              string
	MasterNodeName          string
	MasterSSHPort           int
	MasterSSHUser           string
	MasterSSHPassword       string
	MasterSSHPrivateKeyPath string

	LocalSSHPort int
}

func NewAddNodesOptions() *AddNodesOptions {
	return &AddNodesOptions{
		CommonOptions: options.NewCommonOptions(),
	}
}

// NewCmdAddNodes creates a new add nodes command
func NewCmdAddNodes() *cobra.Command {
	o := NewAddNodesOptions()
	cmd := &cobra.Command{
		Use:   "nodes",
		Short: "Add nodes to the cluster according to the new nodes information from the specified configuration file",
		Run: func(cmd *cobra.Command, args []string) {
			util.CheckErr(o.Complete(cmd, args))
			util.CheckErr(o.Run())
		},
	}

	o.CommonOptions.AddCommonFlag(cmd)
	o.AddFlags(cmd)
	return cmd
}

func (o *AddNodesOptions) Complete(_ *cobra.Command, _ []string) error {
	if o.Artifact == "" {
		o.InstallPackages = false
	}
	return nil
}

func (o *AddNodesOptions) Run() error {
	arg := common.Argument{
		FilePath:         o.ClusterCfgFile,
		KsEnable:         false,
		Debug:            o.CommonOptions.Verbose,
		IgnoreErr:        o.CommonOptions.IgnoreErr,
		SkipConfirmCheck: o.CommonOptions.SkipConfirmCheck,
		SkipPullImages:   o.SkipPullImages,
		InCluster:        o.CommonOptions.InCluster,
		ContainerManager: o.ContainerManager,
		Artifact:         o.Artifact,
		InstallPackages:  o.InstallPackages,
		Namespace:        o.CommonOptions.Namespace,

		KubernetesVersion:       o.Kubernetes,
		RegistryMirrors:         o.RegistryMirrors,
		MasterHost:              o.MasterHost,
		MasterNodeName:          o.MasterNodeName,
		MasterSSHPort:           o.MasterSSHPort,
		MasterSSHUser:           o.MasterSSHUser,
		MasterSSHPassword:       o.MasterSSHPassword,
		MasterSSHPrivateKeyPath: o.MasterSSHPrivateKeyPath,
		LocalSSHPort:            o.LocalSSHPort,
	}
	return pipelines.AddNodes(arg, o.DownloadCmd)
}

func (o *AddNodesOptions) AddFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.ClusterCfgFile, "filename", "f", "", "Path to a configuration file")
	cmd.Flags().BoolVarP(&o.SkipPullImages, "skip-pull-images", "", false, "Skip pre pull images")
	cmd.Flags().StringVarP(&o.ContainerManager, "container-manager", "", "docker", "Container manager: docker, crio, containerd and isula.")
	cmd.Flags().StringVarP(&o.DownloadCmd, "download-cmd", "", "curl -kL -o %s %s",
		`The user defined command to download the necessary binary files. The first param '%s' is output path, the second param '%s', is the URL`)
	cmd.Flags().StringVarP(&o.Artifact, "artifact", "a", "", "Path to a KubeKey artifact")
	cmd.Flags().BoolVarP(&o.InstallPackages, "with-packages", "", false, "install operation system packages by artifact")

	cmd.Flags().StringVarP(&o.Kubernetes, "with-kubernetes", "", "", "Specify a supported version of kubernetes")
	cmd.Flags().StringVarP(&o.RegistryMirrors, "registry-mirrors", "", "", "Docker Container registry mirrors, multiple mirrors are separated by commas")
	cmd.Flags().StringVarP(&o.MasterHost, "master-host", "", "", "master node ip address")
	cmd.Flags().StringVarP(&o.MasterNodeName, "master-node-name", "", "", "master node name for k8s")
	cmd.Flags().IntVarP(&o.MasterSSHPort, "master-ssh-port", "", kubekeyapiv1alpha2.DefaultSSHPort, "master node ip address")
	cmd.Flags().StringVarP(&o.MasterSSHUser, "master-ssh-user", "", "", "master node ssh username")
	cmd.Flags().StringVarP(&o.MasterSSHPassword, "master-ssh-password", "", "", "master node ssh password")
	cmd.Flags().StringVarP(&o.MasterSSHPrivateKeyPath, "master-ssh-private-keyfile", "", "", "master node ssh private key file")
	cmd.Flags().IntVarP(&o.LocalSSHPort, "local-ssh-port", "", kubekeyapiv1alpha2.DefaultSSHPort, "current worker node(localhost) ssh port")
}
