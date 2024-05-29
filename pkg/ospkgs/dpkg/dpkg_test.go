package dpkg

import (
	"github.com/stretchr/testify/require"
	"sort"
	"testing"
)

func TestDependsPackageNames(t *testing.T) {
	/*
		Depends: libc6-dev | libc-dev, libuuid1 (= 2.38.1-5+deb12u1)
		Depends: vim-common (= 2:9.0.1378-2), vim-runtime (= 2:9.0.1378-2), libacl1 (>= 2.2.23), libc6 (>= 2.34), libgpm2 (>= 1.20.7), libselinux1 (>= 3.1~), libsodium23 (>= 1.0.14), libtinfo6 (>= 6)
		Depends: vim-common (= 2:9.0.1378-2), libacl1 (>= 2.2.23), libc6 (>= 2.34), libselinux1 (>= 3.1~), libtinfo6 (>= 6)
		Depends: module-assistant, debhelper (>> 4.0.0), make, bzip2
		Depends: debconf (>= 0.5) | debconf-2.0
		Depends: node-acorn (>= 8.5.0+ds+~cs24.17.6~), node-browserslist, node-chrome-trace-event, node-colorette, node-commander (>= 7~), node-enhanced-resolve, node-es-module-lexer, node-eslint-scope, node-eslint-visitor-keys, node-events, node-graceful-fs, node-import-local, node-interpret (>= 2.2~), node-jest-worker, node-json-parse-better-errors, node-loader-runner, node-mime-types, node-neo-async, node-p-limit, node-rechoir, node-schema-utils, node-serialize-javascript, node-source-map, node-tapable (>= 2.0~), node-types-eslint, node-watchpack, node-webassemblyjs, node-webpack-sources (>= 3.2.1~), nodejs:any, terser
		Depends: libc6 (>= 2.33), libgnutls30 (>= 3.7.2), libidn2-0 (>= 0.6), libnettle8, libpcre2-8-0 (>= 10.22), libpsl5 (>= 0.16.0), libuuid1 (>= 2.16), zlib1g (>= 1:1.1.4)
		Depends: libc6 (>= 2.34), libnewt0.52 (>= 0.52.23), libpopt0 (>= 1.14), libslang2 (>= 2.2.4)
		Depends: lsb-base (>= 1.3-9ubuntu2)
		Depends: libc6 (>= 2.15), libfontconfig1 (>= 2.12.6), libfontenc1, libgl1, libx11-6, libx11-xcb1 (>= 2:1.6.9), libxaw7, libxcb-shape0, libxcb1 (>= 1.6), libxcomposite1 (>= 1:0.3-1), libxext6, libxft2 (>> 2.1.1), libxi6, libxinerama1, libxkbfile1, libxmu6, libxmuu1, libxrandr2 (>= 2:1.2.0), libxrender1, libxt6 (>= 1:1.1.0), libxtst6, libxv1, libxxf86dga1, libxxf86vm1
		Depends: libc6 (>= 2.34), libice6 (>= 1:1.0.0), libx11-6, libxaw7 (>= 2:1.0.14), libxcursor1 (>> 1.1.2), libxext6, libxi6, libxmu6 (>= 2:1.1.3), libxmuu1 (>= 2:1.1.3), libxrandr2 (>= 2:1.5.0), libxt6, libxxf86vm1, cpp
	*/
	tests := []struct {
		line     string
		expected []string
	}{
		{
			line: "libc6-dev | libc-dev, libuuid1 (= 2.38.1-5+deb12u1)",
			expected: []string{
				"libc6-dev", "libc-dev", "libuuid1",
			},
		},
		{
			line:     "",
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.line, func(t *testing.T) {
			r := require.New(t)
			got := parseDependsPackageNames(tt.line)
			sort.Strings(tt.expected)
			sort.Strings(got)
			r.Equal(tt.expected, got)
		})
	}
}
