package com.devsuperior.dslearnbds.resources;

import com.devsuperior.dslearnbds.dto.DeliverRevisionDTO;
import com.devsuperior.dslearnbds.services.DeliverService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping(value = "/deliveries")
public class DeliverResource {

    @Autowired
    private DeliverService deliverService;

    @PreAuthorize("hasAnyRole('ADMIN', 'INSTRUCTOR')") //Pré autorização de EndPoint, apenas para as roles definidas.
    @PutMapping(value = "/{id}")
    public ResponseEntity<Void> saveRevision(@PathVariable Long id, @RequestBody DeliverRevisionDTO dto) {
        deliverService.saveRevision(id, dto);
        return ResponseEntity.noContent().build();
    }
}
