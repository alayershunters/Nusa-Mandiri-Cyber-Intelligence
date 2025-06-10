let cy; // Variabel global untuk instance Cytoscape.js
let rawData = null; // Menyimpan data mentah dari file yang diunggah
let currentElements = []; // Menyimpan elemen yang sedang ditampilkan di grafik

// Definisi warna untuk tipe node dan edge agar grafik lebih informatif
// Pastikan tidak ada koma setelah elemen terakhir di setiap objek
const NODE_COLORS = {
  "threat-actor": "#FF5733", // Merah terang
  "intrusion-set": "#5DADE2", // Biru muda
  identity: "#FFC300", // Kuning
  malware: "#C70039", // Merah gelap
  tool: "#9B59B6", // Ungu
  "attack-pattern": "#2ECC71", // Hijau terang
  indicator: "#3498db", // Biru
  report: "#1ABC9C", // Cyan
  default: "#69a2ff", // Biru default
};

const EDGE_COLORS = {
  uses: "#2c3e50", // Hitam gelap
  "attributed-to": "#e67e22", // Oranye
  indicates: "#3498db", // Biru (sama seperti indicator node)
  default: "#ccc", // Abu-abu default
};

// Fungsi utama untuk memproses file yang diunggah
async function processFile() {
  const fileInput = document.getElementById("fileInput");
  const uploadStatus = document.getElementById("uploadStatus");
  const visualizationSection = document.getElementById("visualization-section");
  const infoPanelSection = document.getElementById("info-panel");
  const analysisReportSection = document.getElementById("analysis-report");
  const filterSection = document.getElementById("filter-section");

  // Reset UI dan sembunyikan semua section hasil
  visualizationSection.style.display = "none";
  infoPanelSection.style.display = "none";
  analysisReportSection.style.display = "none";
  filterSection.style.display = "none";
  uploadStatus.textContent = ""; // Clear previous status
  uploadStatus.className = "status-message"; // Reset classes

  if (fileInput.files.length === 0) {
    uploadStatus.textContent = "Mohon pilih file untuk diunggah.";
    uploadStatus.className = "status-message warning fade-in";
    return;
  }

  const file = fileInput.files[0];
  uploadStatus.textContent = `Memproses file "${file.name}"...`;
  uploadStatus.className = "status-message warning fade-in";

  try {
    const fileContent = await file.text();
    const jsonData = JSON.parse(fileContent);
    rawData = jsonData; // Simpan data mentah
    uploadStatus.textContent = `File "${file.name}" berhasil diunggah dan diproses.`;
    uploadStatus.className = "status-message success fade-in";

    // Tampilkan bagian visualisasi, panel info, dan filter
    visualizationSection.style.display = "flex";
    infoPanelSection.style.display = "block";
    filterSection.style.display = "block";

    // Hanya tampilkan laporan analisis jika itu file attack.json
    if (file.name === "attack.json") {
      analysisReportSection.style.display = "block";
      performAnalysis(jsonData);
    } else {
      // Bersihkan laporan jika file bukan attack.json
      document.getElementById("attackPatternOutput").innerHTML = "";
      document.getElementById("initialCompromiseTechnique").textContent = "";
      document.getElementById("credentialExploitationTools").innerHTML = "";
      document.getElementById("totalCredentialTools").textContent = "";
      document.getElementById("wangDongEmail").textContent = "";
      document.getElementById("fqdnIndicators").innerHTML = "";
      document.getElementById("attackPatternRawOutput").textContent = "";
      document.getElementById("credentialToolsRawOutput").textContent = "";
      document.getElementById("wangDongEmailRawOutput").textContent = "";
      document.getElementById("fqdnIndicatorsRawOutput").textContent = "";
    }

    renderGraph(rawData); // Render grafik dengan data yang diproses
    populateFilters(); // Isi filter setelah grafik dirender
  } catch (error) {
    uploadStatus.textContent = `Error: Gagal memproses file "${file.name}". Pastikan format JSON benar. (${error.message})`;
    uploadStatus.className = "status-message error fade-in";
    console.error("Error processing file:", error);
    // Sembunyikan semua section hasil jika ada error
    visualizationSection.style.display = "none";
    infoPanelSection.style.display = "none";
    analysisReportSection.style.display = "none";
    filterSection.style.display = "none";
  }
}

// Fungsi untuk mengubah data STIX JSON menjadi format yang dipahami Cytoscape.js
function processStixDataForCytoscape(stixData) {
  const elements = [];
  const nodeTypes = new Set();
  const edgeTypes = new Set();

  // Pastikan stixData dan stixData.objects ada
  if (!stixData || !Array.isArray(stixData.objects)) {
    console.warn(
      "Data STIX tidak valid atau tidak memiliki properti 'objects' yang merupakan array."
    );
    return { elements: [], nodeTypes: new Set(), edgeTypes: new Set() };
  }

  // Proses Nodes (objek selain 'relationship')
  stixData.objects.forEach((obj) => {
    if (obj.type !== "relationship") {
      elements.push({
        data: {
          id: obj.id,
          // Prioritas label: name, value, pattern, atau id
          label: obj.name || obj.value || obj.pattern || obj.id,
          type: obj.type, // Tipe STIX object (e.g., 'threat-actor', 'malware')
          fullData: obj, // Simpan seluruh objek STIX untuk detail panel
        },
        group: "nodes",
      });
      nodeTypes.add(obj.type);
    }
  });

  // Proses Edges (Relationship objects)
  stixData.objects.forEach((obj) => {
    if (obj.type === "relationship") {
      elements.push({
        data: {
          id: obj.id,
          source: obj.source_ref,
          target: obj.target_ref,
          label: obj.relationship_type, // Tipe hubungan (e.g., 'uses', 'attributed-to')
          type: obj.type, // Tipe STIX object ('relationship')
          fullData: obj,
        },
        group: "edges",
      });
      edgeTypes.add(obj.relationship_type);
    }
  });

  return { elements, nodeTypes, edgeTypes };
}

// Fungsi untuk merender atau memperbarui grafik Cytoscape.js
function renderGraph(data) {
  const { elements, nodeTypes, edgeTypes } = processStixDataForCytoscape(data);
  currentElements = elements; // Simpan elemen asli untuk filter

  if (cy) {
    cy.destroy(); // Hancurkan instance sebelumnya jika ada
  }

  cy = cytoscape({
    container: document.getElementById("cy"), // Elemen DOM untuk menempatkan grafik
    elements: elements, // Data node dan edge
    style: [
      // Gaya visual untuk node dan edge
      {
        selector: "node",
        style: {
          "background-color": function (ele) {
            return NODE_COLORS[ele.data("type")] || NODE_COLORS["default"];
          },
          label: "data(label)",
          "font-size": "10px",
          color: "#fff",
          "text-valign": "center",
          "text-halign": "center",
          "text-wrap": "wrap",
          "text-max-width": "80px",
          padding: "10px",
          "border-width": "1px",
          "border-color": "#fff",
          "transition-property": "background-color, border-color, transform", // Animasi hover
          "transition-duration": "0.3s",
        },
      },
      {
        selector: "node:selected", // Gaya saat node terpilih
        style: {
          "border-width": "3px",
          "border-color": "#FFD700", // Warna emas
          transform: "scale(1.1)",
          "shadow-blur": "10px",
          "shadow-color": "#FFD700",
          "shadow-opacity": "0.7",
        },
      },
      {
        selector: "edge",
        style: {
          width: 1,
          "line-color": function (ele) {
            return EDGE_COLORS[ele.data("label")] || EDGE_COLORS["default"];
          },
          "target-arrow-color": function (ele) {
            return EDGE_COLORS[ele.data("label")] || EDGE_COLORS["default"];
          },
          "target-arrow-shape": "triangle",
          "curve-style": "bezier",
          label: "data(label)",
          "font-size": "8px",
          color: "#555",
          "text-background-opacity": 0.7,
          "text-background-color": "#f9f9f9",
          "text-background-padding": "2px",
          "edge-text-rotation": "autorotate",
          "transition-property": "line-color, target-arrow-color", // Animasi hover
          "transition-duration": "0.3s",
        },
      },
      {
        selector: ".highlighted", // Gaya untuk node/edge yang di-highlight
        style: {
          "overlay-padding": "5px",
          "overlay-color": "#add8e6",
          "overlay-opacity": 0.4,
        },
      },
      {
        selector: ".faded", // Gaya untuk node/edge yang di-faded
        style: {
          opacity: 0.2,
          "text-opacity": 0,
        },
      },
    ], // Tutup array style
    layout: {
      name: "cose", // Algoritma layout 'cose'
      animate: true,
      animationDuration: 500,
      gravity: 1, // Memperkuat daya tarik
      nodeRepulsion: 200000, // Menyesuaikan jarak antar node
      edgeElasticity: 400,
      idealEdgeLength: 50,
      nodeDimensionsIncludeLabels: true,
      padding: 20, // Padding di sekitar layout grafik
    }, // Tutup objek layout
    minZoom: 0.1,
    maxZoom: 5,
    zoomingEnabled: true,
    userZoomingEnabled: true,
    panningEnabled: true,
    userPanningEnabled: true,
    boxSelectionEnabled: false,
    autounselectify: false, // Mengizinkan node tetap terpilih setelah klik
  }); // Tutup objek cytoscape dan inisialisasi

  // Event listener untuk interaksi dengan node
  cy.on("tap", "node", function (evt) {
    const node = evt.target;
    displayNodeInfo(node.data("fullData"));
    highlightLinkedNodes(node);
  });

  // Event listener untuk klik di area kosong grafik
  cy.on("tap", function (evt) {
    if (evt.target === cy) {
      clearSelectionAndHighlight();
    }
  });

  generateLegend(nodeTypes, edgeTypes);
}

// Fungsi untuk menampilkan informasi detail node yang terpilih
function displayNodeInfo(fullData) {
  const infoContainer = document.getElementById("selected-node-info");
  infoContainer.innerHTML = ""; // Bersihkan sebelumnya

  if (!fullData || Object.keys(fullData).length === 0) {
    infoContainer.innerHTML = "<p>Klik pada node untuk melihat detail.</p>";
    return;
  }

  let html = "<table>";
  for (const key in fullData) {
    // Hanya tampilkan properti yang dimiliki langsung oleh objek
    if (Object.prototype.hasOwnProperty.call(fullData, key)) {
      let value = fullData[key];
      if (Array.isArray(value)) {
        value = value.join(", ");
      } else if (typeof value === "object" && value !== null) {
        // Untuk objek kompleks, tampilkan sebagai string JSON yang diformat
        try {
          value = `<pre style="font-size:0.8em; white-space:pre-wrap; word-break:break-all;">${JSON.stringify(
            value,
            null,
            2
          )}</pre>`;
        } catch (e) {
          value = "[Objek Kompleks]";
        }
      }
      html += `<tr><td class="info-key">${key}:</td><td>${value}</td></tr>`;
    }
  }
  html += "</table>";
  infoContainer.innerHTML = html;
}

// Fungsi untuk menyorot node terkait saat sebuah node dipilih
function highlightLinkedNodes(node) {
  const incomingEdgesList = document.getElementById("incoming-edges");
  const outgoingEdgesList = document.getElementById("outgoing-edges");
  incomingEdgesList.innerHTML = "";
  outgoingEdgesList.innerHTML = "";

  // Hapus semua highlight dan fading sebelumnya
  cy.elements().removeClass("highlighted faded");

  // Dapatkan tetangga node yang dipilih (termasuk node itu sendiri)
  const neighborhood = node.neighborhood().add(node);

  // Fade out semua elemen, lalu highlight tetangga
  cy.elements().addClass("faded");
  neighborhood.removeClass("faded").addClass("highlighted");

  // Tampilkan incoming edges
  node
    .incomers()
    .edges()
    .forEach((edge) => {
      const li = document.createElement("li");
      li.textContent = `(${edge.data("label")}) dari ${cy
        .getElementById(edge.data("source"))
        .data("label")}`;
      incomingEdgesList.appendChild(li);
    });

  // Tampilkan outgoing edges
  node
    .outgoers()
    .edges()
    .forEach((edge) => {
      const li = document.createElement("li");
      li.textContent = `(${edge.data("label")}) ke ${cy
        .getElementById(edge.data("target"))
        .data("label")}`;
      outgoingEdgesList.appendChild(li);
    });
}

// Fungsi untuk membersihkan seleksi dan highlight
function clearSelectionAndHighlight() {
  if (cy) {
    // Pastikan cy sudah diinisialisasi
    cy.elements().removeClass("highlighted faded");
    cy.$("node:selected").unselect(); // Hapus seleksi node
  }
  document.getElementById("selected-node-info").innerHTML =
    "<p>Klik pada node untuk melihat detail.</p>";
  document.getElementById("incoming-edges").innerHTML = "";
  document.getElementById("outgoing-edges").innerHTML = "";
}

// Fungsi untuk membuat legenda berdasarkan tipe node dan edge yang ditemukan
function generateLegend(nodeTypes, edgeTypes) {
  const legendContainer = document.getElementById("legend");
  legendContainer.innerHTML = "<h3>Legenda</h3>";

  let nodeHtml = "<h4>Tipe Node:</h4><ul>";
  Array.from(nodeTypes)
    .sort()
    .forEach((type) => {
      // Urutkan secara alfabetis
      const color = NODE_COLORS[type] || NODE_COLORS["default"];
      nodeHtml += `<li><span class="legend-color-box" style="background-color: ${color};"></span> ${type}</li>`;
    });
  nodeHtml += "</ul>";
  legendContainer.innerHTML += nodeHtml;

  let edgeHtml = "<h4>Tipe Edge (Relationship):</h4><ul>";
  Array.from(edgeTypes)
    .sort()
    .forEach((type) => {
      // Urutkan secara alfabetis
      const color = EDGE_COLORS[type] || EDGE_COLORS["default"];
      edgeHtml += `<li><span class="legend-line" style="background-color: ${color};"></span> ${type}</li>`;
    });
  edgeHtml += "</ul>";
  legendContainer.innerHTML += edgeHtml;
}

// Fungsi untuk mengisi opsi filter berdasarkan tipe node dan edge yang ada di data
function populateFilters() {
  const nodeTypeFilter = document.getElementById("nodeTypeFilter");
  const edgeTypeFilter = document.getElementById("edgeTypeFilter");

  nodeTypeFilter.innerHTML = '<option value="all">Semua Tipe Node</option>';
  edgeTypeFilter.innerHTML = '<option value="all">Semua Tipe Edge</option>';

  const uniqueNodeTypes = new Set();
  const uniqueEdgeTypes = new Set();

  // Iterasi melalui rawData.objects untuk mendapatkan tipe unik
  if (rawData && Array.isArray(rawData.objects)) {
    rawData.objects.forEach((obj) => {
      if (obj.type !== "relationship") {
        uniqueNodeTypes.add(obj.type);
      } else {
        uniqueEdgeTypes.add(obj.relationship_type);
      }
    });
  }

  Array.from(uniqueNodeTypes)
    .sort()
    .forEach((type) => {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      nodeTypeFilter.appendChild(option);
    });

  Array.from(uniqueEdgeTypes)
    .sort()
    .forEach((type) => {
      const option = document.createElement("option");
      option.value = type;
      option.textContent = type;
      edgeTypeFilter.appendChild(option);
    });
}

// Fungsi untuk menerapkan filter pada grafik
function applyFilter() {
  if (!cy) return; // Pastikan Cytoscape instance sudah ada

  const selectedNodeType = document.getElementById("nodeTypeFilter").value;
  const selectedEdgeType = document.getElementById("edgeTypeFilter").value;

  cy.elements().removeClass("faded"); // Bersihkan fading sebelumnya

  // Sembunyikan semua elemen terlebih dahulu
  cy.elements().hide();

  // Tampilkan node berdasarkan filter tipe node
  let nodesToShow = cy.nodes();
  if (selectedNodeType !== "all") {
    nodesToShow = nodesToShow.filter(
      (node) => node.data("type") === selectedNodeType
    );
  }
  nodesToShow.show();

  // Tampilkan edge berdasarkan filter tipe edge
  let edgesToShow = cy.edges();
  if (selectedEdgeType !== "all") {
    edgesToShow = edgesToShow.filter(
      (edge) => edge.data("label") === selectedEdgeType
    );
  }
  edgesToShow.show();

  // Pastikan node yang terhubung dengan edge yang terlihat juga ditampilkan
  edgesToShow.connectedNodes().show();

  // Terapkan layout ulang hanya pada elemen yang terlihat
  const visibleElements = cy.elements(":visible");
  if (visibleElements.length > 0) {
    visibleElements.layout({ name: "cose" }).run();
  }
}

function resetFilters() {
  document.getElementById("nodeTypeFilter").value = "all";
  document.getElementById("edgeTypeFilter").value = "all";
  applyFilter();
}

// --- Fungsi Analisis Khusus untuk attack.json (Tugas 1 dari PDF) ---

function performAnalysis(data) {
  const objects = data.objects;

  // 1. Pola Serangan (Attack Patterns) & Fase Kill Chain
  const attackPatterns = objects.filter((obj) => obj.type === "attack-pattern");
  const attackPatternOutput = document.getElementById("attackPatternOutput");
  attackPatternOutput.innerHTML = "";
  const attackPatternRawOutput = document.getElementById(
    "attackPatternRawOutput"
  );
  let attackPatternRawText = "";

  attackPatterns.forEach((pattern) => {
    const killChainPhases = pattern.kill_chain_phases
      ? pattern.kill_chain_phases.map((phase) => phase.phase_name).join(", ")
      : "Tidak ada";
    attackPatternOutput.innerHTML += `<p><strong>Nama:</strong> ${pattern.name}<br><strong>Fase Kill Chain:</strong> ${killChainPhases}</p>`;
    attackPatternRawText += `Nama: ${pattern.name}\nFase Kill Chain: ${killChainPhases}\n\n`;
  });

  const initialCompromisePattern = attackPatterns.find(
    (pattern) => pattern.name === "Initial Compromise"
  );
  // Memastikan deskripsi ada sebelum memisahkan
  document.getElementById("initialCompromiseTechnique").textContent =
    initialCompromisePattern && initialCompromisePattern.description
      ? initialCompromisePattern.description.split(".")[0] + "."
      : "Tidak Ditemukan";

  attackPatternRawOutput.textContent = attackPatternRawText;

  // 2. Alat Eksploitasi Kredensial (Credential Exploitation Tools)
  const credentialTools = objects.filter(
    (obj) =>
      obj.type === "tool" &&
      obj.tool_types &&
      obj.tool_types.includes("credential-exploitation")
  );
  const credentialExploitationToolsList = document.getElementById(
    "credentialExploitationTools"
  );
  credentialExploitationToolsList.innerHTML = "";
  const credentialToolsRawOutput = document.getElementById(
    "credentialToolsRawOutput"
  );
  let credentialToolsRawText = "";

  if (credentialTools.length > 0) {
    credentialTools.forEach((tool) => {
      const listItem = document.createElement("li");
      listItem.textContent = tool.name;
      credentialExploitationToolsList.appendChild(listItem);
      credentialToolsRawText += tool.name + "\n";
    });
  } else {
    credentialToolsRawText =
      "Tidak ada alat eksploitasi kredensial yang ditemukan.";
  }

  document.getElementById("totalCredentialTools").textContent =
    credentialTools.length;
  credentialToolsRawOutput.textContent = credentialToolsRawText;

  // 3. Alamat Email Identitas "Wang Dong"
  const wangDongIdentity = objects.find(
    (obj) => obj.type === "identity" && obj.name === "Wang Dong"
  );
  const wangDongEmail =
    wangDongIdentity && wangDongIdentity.contact_information
      ? wangDongIdentity.contact_information
      : "Tidak Ditemukan";
  document.getElementById("wangDongEmail").textContent = wangDongEmail;
  document.getElementById("wangDongEmailRawOutput").textContent = wangDongEmail;

  // 4. Indikator FQDN (.org)
  const fqdnIndicators = objects.filter(
    (obj) =>
      obj.type === "indicator" && obj.pattern && obj.pattern.includes(".org']")
  );
  const fqdnIndicatorsList = document.getElementById("fqdnIndicators");
  fqdnIndicatorsList.innerHTML = "";
  const fqdnIndicatorsRawOutput = document.getElementById(
    "fqdnIndicatorsRawOutput"
  );
  let fqdnIndicatorsRawText = "";

  if (fqdnIndicators.length > 0) {
    fqdnIndicators.forEach((indicator) => {
      const listItem = document.createElement("li");
      // Extract the domain name from the pattern string: [domain-name:value = 'hugesoft.org']
      const match = indicator.pattern.match(/'([^']+)'/);
      if (match && match[1]) {
        listItem.textContent = match[1];
        fqdnIndicatorsList.appendChild(listItem);
        fqdnIndicatorsRawText += match[1] + "\n";
      }
    });
  } else {
    fqdnIndicatorsRawText = "Tidak ada indikator FQDN (.org) yang ditemukan.";
  }

  fqdnIndicatorsRawOutput.textContent = fqdnIndicatorsRawText;
}
